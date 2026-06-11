"""Interactive AD Ops game HTTP server (stdlib only).

Serves the game SPA and drives real admapper CLI phases from the browser.
Patterns implemented (see game_ui.py header comment): mission briefing, animated
terminal via SSE, phase-gated actions, live graph refresh after each op.
"""

from __future__ import annotations

import json
import queue
import shlex
import shutil
import subprocess
import sys
import threading
import time
import errno
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from admapper.core.game_mode import enable_game_mode, game_subprocess_env
from admapper.graph.game_ui import build_game_html, build_game_payload
from admapper.graph.terminal_filter import GameTerminalFilter
from admapper.intel.user_match import refresh_workspace_intel


class GameContext:
    """Per-server workspace state, event bus, and op lock."""

    def __init__(
        self,
        *,
        ws_path: Path,
        workspace: str,
        domain: str | None,
        owned_users: list[str],
        pivot_user: str | None,
        host: str | None,
    ) -> None:
        self.ws_path = ws_path
        self.workspace = workspace
        self.domain = domain
        self.owned_users = list(owned_users)
        self.pivot_user = pivot_user
        self.host = host
        self.events: queue.Queue[dict[str, Any]] = queue.Queue()
        self.op_lock = threading.Lock()
        self.running = False
        self.terminal_filter = GameTerminalFilter()

    def emit(self, line: str, *, kind: str = "log") -> None:
        self.events.put({"type": kind, "line": line, "ts": time.time()})

    def refresh_payload(self) -> dict[str, Any]:
        refresh_workspace_intel(self.ws_path)
        state_path = self.ws_path / "state.json"
        if state_path.is_file():
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if state.get("owned_users"):
                self.owned_users = list(state["owned_users"])
            if state.get("pivot_user"):
                self.pivot_user = str(state["pivot_user"])
            if state.get("domain"):
                self.domain = str(state["domain"])
        return build_game_payload(
            self.ws_path,
            workspace=self.workspace,
            domain=self.domain,
            owned_users=self.owned_users,
            pivot_user=self.pivot_user,
        )

    def _admapper_cmd(self, *args: str) -> list[str]:
        exe = shutil.which("admapper")
        if exe:
            return [exe, *args]
        return [sys.executable, "-m", "admapper.cli.main", *args]

    def _dc_ip(self) -> str:
        if self.host:
            return self.host
        unauth_path = self.ws_path / "unauth_scan.json"
        if unauth_path.is_file():
            data = json.loads(unauth_path.read_text(encoding="utf-8"))
            for host in data.get("hosts") or []:
                if host.get("is_domain_controller"):
                    return str(host.get("address", ""))
            hosts = data.get("hosts") or []
            if hosts:
                return str(hosts[0].get("address", ""))
        return ""

    def _compact_cmd(self, cmd: list[str]) -> str:
        """Hide full local paths and passwords from the game terminal."""
        shown: list[str] = []
        skip_next = False
        for i, part in enumerate(cmd):
            if skip_next:
                skip_next = False
                continue
            if part in {"-p", "--password"}:
                shown.append(part)
                shown.append("'***'")
                skip_next = True
                continue
            if part.startswith("/") and "admapper" in part:
                shown.append("admapper")
                continue
            shown.append(part)
        return " ".join(shlex.quote(a) for a in shown)

    def _run_subprocess(self, cmd: list[str]) -> int:
        self.terminal_filter.reset()
        self.emit(self._compact_cmd(cmd), kind="cmd")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=game_subprocess_env(),
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            filtered = self.terminal_filter.process(line.rstrip())
            if filtered:
                kind = "log"
                if filtered.startswith("✓"):
                    kind = "done"
                elif filtered.startswith("!") or filtered.startswith("✗"):
                    kind = "error"
                elif filtered.startswith("→") or filtered.startswith("──"):
                    kind = "phase"
                self.emit(filtered, kind=kind)
        code = proc.wait()
        self.emit(f"fin · código {code}", kind="done" if code == 0 else "error")
        return code

    def _persist_target_ip(self, ip: str) -> None:
        from admapper.cli.commands import dispatch
        from admapper.core.session import Session

        session = Session.bootstrap()
        session.select_workspace(self.workspace, create=False)
        dispatch(session, f"set hosts {ip}")
        session.persist_workspace()
        self.host = ip

    def run_scan(self, *, ip: str | None = None) -> None:
        target = (ip or self._dc_ip()).strip()
        if not target:
            self.emit("sin IP — escribe la IP del objetivo en el terminal de arranque", kind="error")
            return
        self._persist_target_ip(target)
        cmd = self._admapper_cmd("scan", "-H", target, "-w", self.workspace)
        self._run_subprocess(cmd)

    def run_auth(self, username: str, password: str) -> None:
        ip = self._dc_ip()
        if not ip:
            self.emit("sin IP de DC", kind="error")
            return
        if not username or not password:
            self.emit("usuario y contraseña requeridos", kind="error")
            return
        cmd = self._admapper_cmd(
            "run",
            "-H",
            ip,
            "-u",
            username,
            "-p",
            password,
            "-w",
            self.workspace,
        )
        if self.domain:
            cmd.extend(["-d", self.domain])
        self._run_subprocess(cmd)

    def _run_workspace_script(self, script: str, *, label: str) -> None:
        """Run in-process op with stdout routed through the game terminal filter."""
        import io
        from contextlib import redirect_stdout

        from admapper.core.session import Session

        self.emit(label, kind="cmd")
        session = Session.bootstrap()
        session.select_workspace(self.workspace, create=False)
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                exec(script, {"session": session, "__name__": "__main__"})  # noqa: S102
            session.persist_workspace()
            for line in buf.getvalue().splitlines():
                filtered = self.terminal_filter.process(line.rstrip())
                if filtered:
                    kind = "done" if filtered.startswith("✓") else "log"
                    self.emit(filtered, kind=kind)
            self.emit("fin · código 0", kind="done")
        except Exception as exc:  # noqa: BLE001
            self.emit(str(exc), kind="error")
            self.emit("fin · código 1", kind="error")

    def run_enum_users(self) -> None:
        self._run_workspace_script(
            "from admapper.enumeration.scan import run_user_enumeration\n"
            "run_user_enumeration(session)",
            label="enum users",
        )

    def run_asreproast(self) -> None:
        self._run_workspace_script(
            "from admapper.creds.asreproast import run_asreproast\n"
            "run_asreproast(session)",
            label="asreproast",
        )

    def run_kerberoast(self) -> None:
        self._run_workspace_script(
            "from admapper.creds.kerberoast import run_kerberoast\n"
            "run_kerberoast(session)",
            label="kerberoast",
        )

    def run_spray(self, password: str) -> None:
        if not password:
            self.emit("contraseña requerida para spray", kind="error")
            return
        import base64

        pw_b64 = base64.b64encode(password.encode()).decode()
        self._run_workspace_script(
            "import base64\n"
            "from admapper.creds.spray import run_spray\n"
            f"run_spray(session, base64.b64decode('{pw_b64}').decode())",
            label="spray '***'",
        )

    def run_exploit(self) -> None:
        cmd = self._admapper_cmd("exploit", "-w", self.workspace)
        self._run_subprocess(cmd)

    def run_acls(self) -> None:
        from admapper.acl.analyze import run_acl_analysis
        from admapper.core.session import Session

        session = Session.bootstrap()
        session.select_workspace(self.workspace, create=False)
        try:
            run_acl_analysis(session)
            session.persist_workspace()
            self.emit("ACL analysis complete", kind="done")
        except (ValueError, RuntimeError) as exc:
            self.emit(str(exc), kind="error")

    def set_pivot(self, username: str) -> None:
        from admapper.core.session import Session
        from admapper.escalate.analyze import set_pivot_user
        from admapper.graph.identity_lens import build_selectable_identities

        session = Session.bootstrap()
        session.select_workspace(self.workspace, create=False)
        domain = session.workspace.domain or self.domain or ""
        selectable = build_selectable_identities(
            self.ws_path,
            domain=domain,
            owned_users=list(session.workspace.owned_users or []),
        )
        match = next(
            (i for i in selectable if str(i.get("username", "")).lower() == username.lower()),
            None,
        )
        if not match:
            self.emit(
                f"sin perfil para {username} — enumera o compromete primero",
                kind="error",
            )
            return
        if match.get("selectable") == "view":
            self.emit(
                f"{username} es objetivo enum — perfil lectura en UI, no pivot",
                kind="error",
            )
            return
        set_pivot_user(session, username)
        if match.get("selectable") == "verify":
            self.emit(
                f"enfoque → {username} (loot pendiente — verifica credencial)",
                kind="phase",
            )
        else:
            self.emit(f"perfil activo → {username}", kind="done")
        self.pivot_user = username

    def run_brief(self, *, auto: bool = False) -> None:
        from admapper.cli.brief import run_brief
        from admapper.core.session import Session

        session = Session.bootstrap()
        session.select_workspace(self.workspace, create=False)
        try:
            run_brief(session, refresh=True, auto=auto)
            session.persist_workspace()
            self.emit("brief complete", kind="done")
        except (ValueError, RuntimeError) as exc:
            self.emit(str(exc), kind="error")


def _json_response(handler: BaseHTTPRequestHandler, code: int, payload: Any) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return {}


def make_handler(ctx: GameContext) -> type[BaseHTTPRequestHandler]:
    class GameHandler(BaseHTTPRequestHandler):
        server_version = "ADOpsGame/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _start_background(self, fn: Callable[[], None]) -> None:
            if ctx.running:
                _json_response(self, 409, {"error": "operación en curso"})
                return
            if not ctx.op_lock.acquire(blocking=False):
                _json_response(self, 409, {"error": "operación en curso"})
                return

            def wrapper() -> None:
                ctx.running = True
                ctx.emit("─── inicio operación ───", kind="phase")
                try:
                    fn()
                    refresh_workspace_intel(ctx.ws_path)
                    ctx.emit("─── operación finalizada ───", kind="phase")
                    ctx.emit(json.dumps({"refresh": True}), kind="state")
                except Exception as exc:  # noqa: BLE001 — surface to terminal UI
                    ctx.emit(f"ERROR: {exc}", kind="error")
                finally:
                    ctx.running = False
                    ctx.op_lock.release()

            threading.Thread(target=wrapper, daemon=True).start()
            _json_response(self, 202, {"status": "started"})

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path in {"/", "/ad_ops.html", "/index.html"}:
                html = build_game_html(
                    ctx.ws_path,
                    workspace=ctx.workspace,
                    domain=ctx.domain,
                    owned_users=ctx.owned_users,
                    pivot_user=ctx.pivot_user,
                    api_mode=True,
                )
                body = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/api/state":
                payload = ctx.refresh_payload()
                _json_response(self, 200, payload)
                return

            if path == "/api/events":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                while True:
                    try:
                        evt = ctx.events.get(timeout=12.0)
                        payload = f"data: {json.dumps(evt, ensure_ascii=False)}\n\n"
                    except queue.Empty:
                        payload = ": ping\n\n"
                    try:
                        self.wfile.write(payload.encode("utf-8"))
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        break
                return

            if path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return

            self.send_error(404)

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            body = _read_json_body(self)

            if path == "/api/scan":
                ip = str(body.get("ip") or "").strip()
                self._start_background(lambda: ctx.run_scan(ip=ip or None))
                return

            if path == "/api/run":
                self._start_background(
                    lambda: ctx.run_auth(
                        str(body.get("username", "")).strip(),
                        str(body.get("password", "")),
                    )
                )
                return

            if path == "/api/exploit":
                self._start_background(ctx.run_exploit)
                return

            if path == "/api/acls":
                self._start_background(ctx.run_acls)
                return

            if path == "/api/brief":
                auto = bool(body.get("auto", False))
                self._start_background(lambda: ctx.run_brief(auto=auto))
                return

            if path == "/api/pivot":
                user = str(body.get("username", "")).strip()
                if not user:
                    _json_response(self, 400, {"error": "username required"})
                    return
                self._start_background(lambda: ctx.set_pivot(user))
                return

            if path == "/api/enum":
                self._start_background(ctx.run_enum_users)
                return

            if path == "/api/asreproast":
                self._start_background(ctx.run_asreproast)
                return

            if path == "/api/kerberoast":
                self._start_background(ctx.run_kerberoast)
                return

            if path == "/api/spray":
                password = str(body.get("password", ""))
                if not password:
                    _json_response(self, 400, {"error": "password required"})
                    return
                self._start_background(lambda: ctx.run_spray(password))
                return

            self.send_error(404)

    return GameHandler


def run_game_server(
    *,
    ws_path: Path,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
    host: str | None = None,
    port: int = 8766,
    open_browser: bool = True,
) -> None:
    """Start blocking game server until KeyboardInterrupt."""
    import webbrowser

    enable_game_mode()
    refresh_workspace_intel(ws_path)
    ctx = GameContext(
        ws_path=ws_path,
        workspace=workspace,
        domain=domain,
        owned_users=list(owned_users or []),
        pivot_user=pivot_user,
        host=host,
    )
    handler = make_handler(ctx)

    class _ReuseServer(ThreadingHTTPServer):
        allow_reuse_address = True

    httpd: ThreadingHTTPServer | None = None
    bound_port = port
    for candidate in range(port, port + 10):
        try:
            httpd = _ReuseServer(("127.0.0.1", candidate), handler)
            bound_port = candidate
            break
        except OSError as exc:
            if exc.errno not in {errno.EADDRINUSE, 48}:
                raise
    if httpd is None:
        raise OSError(f"puertos {port}–{port + 9} ocupados — cierra otra instancia de admapper game")

    url = f"http://127.0.0.1:{bound_port}/"
    from admapper.core.output import print_info, print_success

    print_success(f"AD Ops game → {url}")
    print_info("Ctrl+C para detener el servidor")
    print_info(
        "modo juego: sin sudo — prep local: admapper sync-dc -H <DC>  "
        "(o panel «Tu máquina» en el juego)"
    )
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
