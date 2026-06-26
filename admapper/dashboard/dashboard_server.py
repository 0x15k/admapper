"""Interactive AD Ops dashboard HTTP server (stdlib only).

Serves the dashboard SPA and drives real admapper CLI phases from the browser.
Patterns implemented (see ops_ui.py header comment): mission briefing, animated
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

from admapper.support.dashboard_mode import enable_dashboard_mode, dashboard_subprocess_env
from admapper.models.workspace import OperationMode


def _server_log(msg: str) -> None:
    """Append a timestamped line to the server debug log."""
    try:
        with Path("/tmp/admapper_server.log").open("a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except OSError:
        pass


from admapper.dashboard.ops_progress import OpsProgress
from admapper.dashboard.dashboard_html import build_dashboard_html
from admapper.dashboard.ops_ui import build_ops_payload
from admapper.dashboard.terminal_filter import TerminalFilter
from admapper.analysis.user_match import refresh_workspace_intel


def _load_json_safe(path: Path) -> dict[str, Any]:
    """Load JSON from path, return empty dict on any error."""
    try:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        pass
    return {}


class DashboardContext:
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
        self._initial_owned_users = list(owned_users)
        self.pivot_user = pivot_user
        self.host = host
        self.events: queue.Queue[dict[str, Any]] = queue.Queue()
        self.op_lock = threading.Lock()
        self.running = False
        self.terminal_filter = TerminalFilter()
        saved = OpsProgress.load(self.ws_path)
        if saved.scan or saved.enum_users:
            self.progress = saved
        else:
            self.progress = OpsProgress.fresh()
            self.progress.save(self.ws_path)

    def emit(self, line: str, *, kind: str = "log") -> None:
        self.events.put({"type": kind, "line": line, "ts": time.time()})

    def refresh_payload(self) -> dict[str, Any]:
        self._sync_offline_cracked_hashes()
        refresh_workspace_intel(self.ws_path)
        self.progress = OpsProgress.load(self.ws_path)
        self._sync_loot_progress()

        # Sync verified/owned users into self.progress from state.json & credentials.json
        state_path = self.ws_path / "state.json"
        if state_path.is_file():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
                state_owned = list(state.get("owned_users") or [])
                for u in state_owned:
                    if u.lower() not in {o.lower() for o in self.progress.owned_users}:
                        self.progress.owned_users.append(u)
                    if u.lower() not in {o.lower() for o in self.progress.verified_users}:
                        self.progress.verified_users.append(u)
            except Exception:
                pass

        creds_path = self.ws_path / "credentials.json"
        if creds_path.is_file():
            try:
                cdata = json.loads(creds_path.read_text(encoding="utf-8"))
                for c in cdata.get("credentials") or []:
                    username = c.get("username")
                    if str(c.get("status")) == "valid" and username:
                        username_s = str(username)
                        if username_s.lower() not in {u.lower() for u in self.progress.verified_users}:
                            self.progress.verified_users.append(username_s)
                        if username_s.lower() not in {u.lower() for u in self.progress.owned_users}:
                            self.progress.owned_users.append(username_s)
            except Exception:
                pass

        self.progress.save(self.ws_path)

        # Keep initial owned/pivot context even if ops_progress file is empty.
        file_owned = set(self.progress.owned_users)
        initial_owned = {u.lower() for u in (self._initial_owned_users or [])}
        merged_owned = sorted(file_owned | initial_owned, key=str.lower)
        self.owned_users = list(merged_owned)

        # Sync pivot and owned from state.json / credentials.json when context
        # was not established via CLI flags (e.g. `admapper web -H <ip>` only).
        state_path = self.ws_path / "state.json"
        if state_path.is_file():
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if state.get("domain"):
                self.domain = str(state["domain"])
            if state.get("hosts") and not self.host:
                self.host = str(state["hosts"])
            # Inherit owned_users from state.json when progress is empty.
            state_owned = list(state.get("owned_users") or [])
            if state_owned:
                for u in state_owned:
                    if u.lower() not in {o.lower() for o in self.owned_users}:
                        self.owned_users.append(u)
            # Inherit pivot_user from state.json when not set.
            if not self.pivot_user and state.get("pivot_user"):
                self.pivot_user = str(state["pivot_user"])

        # Derive pivot from valid credentials when still unset.
        if not self.pivot_user:
            creds_path = self.ws_path / "credentials.json"
            if creds_path.is_file():
                try:
                    cdata = json.loads(creds_path.read_text(encoding="utf-8"))
                    for c in cdata.get("credentials") or []:
                        if str(c.get("status")) == "valid" and c.get("username"):
                            self.pivot_user = str(c["username"])
                            if self.pivot_user.lower() not in {
                                u.lower() for u in self.owned_users
                            }:
                                self.owned_users.append(self.pivot_user)
                            break
                except (json.JSONDecodeError, OSError):
                    pass

        if self.pivot_user and self.pivot_user.lower() not in {
            u.lower() for u in self.owned_users
        }:
            verified = self.progress.verified_set()
            if self.pivot_user.lower() not in verified:
                self.pivot_user = self.owned_users[-1] if self.owned_users else None

        # Infer owned_methods from workspace artifacts for users missing a method
        self._infer_owned_methods()

        payload = build_ops_payload(
            self.ws_path,
            workspace=self.workspace,
            domain=self.domain,
            owned_users=self.owned_users,
            pivot_user=self.pivot_user,
            ops_progress=self.progress,
            target_ip=self.host,
        )
        payload["running"] = bool(self.running)
        payload["busy"] = bool(self.op_lock.locked())
        return payload

    def _sync_loot_progress(self) -> None:
        manifest_path = self.ws_path / "loot_manifest.json"
        if not manifest_path.is_file():
            return
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        users = [
            str(item.get("username", ""))
            for item in data.get("parsed_credentials") or []
            if item.get("username")
        ]
        if users or data.get("file_count"):
            self.progress.remember_loot_users(users)
            self.progress.save(self.ws_path)

    def _sync_spray_owned(self) -> None:
        """After spray, read spray_report.json and mark hits as owned."""
        report_path = self.ws_path / "spray_report.json"
        if not report_path.is_file():
            return
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        for user in data.get("hits") or []:
            user_s = str(user).strip()
            if user_s:
                self.progress.remember_owned(user_s, method="spray")
                if user_s.lower() not in {u.lower() for u in self.owned_users}:
                    self.owned_users.append(user_s)
        self.progress.save(self.ws_path)

    def _sync_exploit_owned(self) -> None:
        """After exploit, read exploit_log.json and mark gained accounts as owned."""
        log_path = self.ws_path / "exploit_log.json"
        if not log_path.is_file():
            return
        try:
            data = json.loads(log_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        for item in data.get("new_hashes") or []:
            account = str(item.get("account", "")).strip()
            if account:
                self.progress.remember_owned(account, method="exploit_acl")
                if account.lower() not in {u.lower() for u in self.owned_users}:
                    self.owned_users.append(account)
        for user in data.get("new_users") or []:
            user_s = str(user).strip()
            if user_s:
                self.progress.remember_owned(user_s, method="exploit_acl")
                if user_s.lower() not in {u.lower() for u in self.owned_users}:
                    self.owned_users.append(user_s)
        self.progress.save(self.ws_path)

    def _sync_new_creds_owned(self, *, source: str, method: str) -> None:
        """After roast/other credential attacks, sync newly valid creds as owned."""
        creds_path = self.ws_path / "credentials.json"
        if not creds_path.is_file():
            return
        try:
            data = json.loads(creds_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        for c in data.get("credentials") or []:
            cred_source = str(c.get("source", ""))
            username = str(c.get("username", "")).strip()
            status = str(c.get("status", ""))
            if cred_source == source and username:
                # Even unverified creds from roast are worth tracking
                self.progress.remember_owned(username, method=method)
                if username.lower() not in {u.lower() for u in self.owned_users}:
                    self.owned_users.append(username)
        self.progress.save(self.ws_path)

    def _sync_offline_cracked_hashes(self) -> None:
        """Scan for offline cracked hashes from John/Hashcat files and update credentials/progress."""
        loot_dir = self.ws_path / "loot"
        cracked_files = [
            loot_dir / "cracked.txt",
            loot_dir / "hashes.txt.cracked",
        ]
        
        # Check if any cracked files exist
        has_files = False
        for f in cracked_files:
            if f.is_file():
                has_files = True
                break
        if not has_files:
            return

        # Load all known users to map usernames case-insensitively
        known_users: dict[str, str] = {}
        # From state.json
        state_path = self.ws_path / "state.json"
        if state_path.is_file():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
                for u in state.get("owned_users") or []:
                    known_users[u.lower()] = u
            except Exception:
                pass

        # From auth_inventory.json
        inv_path = self.ws_path / "auth_inventory.json"
        if inv_path.is_file():
            try:
                inv = json.loads(inv_path.read_text(encoding="utf-8"))
                for u in inv.get("users") or []:
                    name = u.get("username")
                    if name:
                        known_users[name.lower()] = name
            except Exception:
                pass

        # From credentials.json
        creds_path = self.ws_path / "credentials.json"
        if creds_path.is_file():
            try:
                cdata = json.loads(creds_path.read_text(encoding="utf-8"))
                for c in cdata.get("credentials") or []:
                    name = c.get("username")
                    if name:
                        known_users[name.lower()] = name
            except Exception:
                pass

        # Map hashes to usernames
        hash_to_user: dict[str, str] = {}
        # From kerberoast_hashes.json
        krb_path = self.ws_path / "kerberoast_hashes.json"
        if krb_path.is_file():
            try:
                data = json.loads(krb_path.read_text(encoding="utf-8"))
                for h in data.get("hashes") or []:
                    username = h.get("username")
                    hashcat = h.get("hashcat")
                    if username and hashcat:
                        hash_to_user[hashcat.strip().lower()] = username
            except Exception:
                pass

        # From asreproast_hashes.json
        asrep_path = self.ws_path / "asreproast_hashes.json"
        if asrep_path.is_file():
            try:
                data = json.loads(asrep_path.read_text(encoding="utf-8"))
                for h in data.get("hashes") or []:
                    username = h.get("username")
                    hashcat = h.get("hashcat")
                    if username and hashcat:
                        hash_to_user[hashcat.strip().lower()] = username
            except Exception:
                pass

        # From exploit_log.json (NTLM hashes)
        exploit_path = self.ws_path / "exploit_log.json"
        if exploit_path.is_file():
            try:
                data = json.loads(exploit_path.read_text(encoding="utf-8"))
                for h in data.get("new_hashes") or []:
                    account = h.get("account")
                    nthash = h.get("nthash")
                    if account and nthash:
                        hash_to_user[nthash.strip().lower()] = account
            except Exception:
                pass

        # From credentials.json (NTLM hashes)
        if creds_path.is_file():
            try:
                cdata = json.loads(creds_path.read_text(encoding="utf-8"))
                for c in cdata.get("credentials") or []:
                    username = c.get("username")
                    secret = c.get("secret")
                    if username and secret and c.get("type") == "ntlm":
                        hash_to_user[secret.strip().lower()] = username
            except Exception:
                pass

        # Parse cracked passwords
        cracked_creds: dict[str, str] = {} # username -> password
        import re

        def extract_user_from_krb_hash(line: str) -> str | None:
            match = re.search(r"\$krb5asrep\$[^$]*\$([^$]+)@", line)
            if match:
                return match.group(1)
            match = re.search(r"\$krb5tgs\$23\$\*[^$]+\$[^$]+\$([^*]+)\*", line)
            if match:
                return match.group(1)
            return None

        for f in cracked_files:
            if not f.is_file():
                continue
            try:
                lines = f.read_text(encoding="utf-8").splitlines()
                for line in lines:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    parts = line.split(":", 1)
                    key = parts[0].strip()
                    password = parts[1].strip()
                    if not key or not password:
                        continue
                    
                    # 1. Direct username check
                    if key.lower() in known_users:
                        cracked_creds[known_users[key.lower()]] = password
                        continue
                    
                    # 2. Domain clean check
                    key_clean = key
                    if "@" in key_clean:
                        key_clean = key_clean.split("@", 1)[0]
                    if "\\" in key_clean:
                        key_clean = key_clean.split("\\", 1)[1]
                    if key_clean.lower() in known_users:
                        cracked_creds[known_users[key_clean.lower()]] = password
                        continue
                        
                    # 3. Direct hash check
                    if key.lower() in hash_to_user:
                        cracked_creds[hash_to_user[key.lower()]] = password
                        continue
                        
                    # 4. Kerberos hash parsed user check
                    parsed_user = extract_user_from_krb_hash(key)
                    if parsed_user and parsed_user.lower() in known_users:
                        cracked_creds[known_users[parsed_user.lower()]] = password
                        continue
            except Exception:
                pass

        if not cracked_creds:
            return

        # Load existing credentials.json
        creds_data = {"credentials": []}
        if creds_path.is_file():
            try:
                creds_data = json.loads(creds_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        creds_list = creds_data.setdefault("credentials", [])
        updated = False

        for uname, pwd in cracked_creds.items():
            # Check if we already have this user in credentials.json
            found = False
            for c in creds_list:
                if str(c.get("username", "")).lower() == uname.lower():
                    found = True
                    if c.get("status") != "valid" or c.get("secret") != pwd:
                        c["secret"] = pwd
                        c["status"] = "valid"
                        c["type"] = "password"
                        updated = True
                    break
            if not found:
                import uuid
                creds_list.append({
                    "id": uuid.uuid4().hex[:12],
                    "username": uname,
                    "secret": pwd,
                    "type": "password",
                    "domain": self.domain,
                    "status": "valid",
                    "source": "cracked",
                })
                updated = True

        if updated:
            try:
                creds_path.write_text(json.dumps(creds_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            except Exception:
                pass

            # Sync progress and context
            for uname in cracked_creds:
                self.progress.remember_owned(uname, method="password")
                if uname.lower() not in {u.lower() for u in self.owned_users}:
                    self.owned_users.append(uname)
                if uname.lower() not in {u.lower() for u in self.progress.verified_users}:
                    self.progress.verified_users.append(uname)

            try:
                self.progress.save(self.ws_path)
            except Exception:
                pass

            # Update owned users in graph.json and state.json (best-effort)
            try:
                from admapper.support.session import Session
                from admapper.escalate.analyze import mark_user_owned
                session = Session.bootstrap()
                session.select_workspace(self.workspace, create=True)
                for uname in cracked_creds:
                    if self.ws_path.joinpath("graph.json").is_file():
                        try:
                            mark_user_owned(session, uname, refresh=True)
                        except Exception:
                            pass
                session.persist_workspace()
            except Exception:
                pass

    def _infer_owned_methods(self) -> None:
        """Backfill owned_methods for users that don't have a method yet."""
        known = set(self.progress.owned_methods.keys())
        need = {u.lower() for u in self.progress.owned_users} - known
        if not need:
            return
        # Infer from credentials.json
        creds_path = self.ws_path / "credentials.json"
        if creds_path.is_file():
            try:
                cdata = json.loads(creds_path.read_text(encoding="utf-8"))
                for c in cdata.get("credentials") or []:
                    uname = str(c.get("username", "")).strip().lower()
                    if uname not in need:
                        continue
                    cred_type = str(c.get("type", ""))
                    source = str(c.get("source", ""))
                    if source in {"spray"}:
                        method = "spray"
                    elif source in {"kerberoast"}:
                        method = "kerberoast"
                    elif source in {"asreproast"}:
                        method = "asreproast"
                    elif cred_type == "ntlm":
                        method = "ntlm_hash"
                    elif cred_type == "kerberos":
                        method = "kerberos"
                    else:
                        method = "password"
                    self.progress.owned_methods[uname] = method
                    need.discard(uname)
            except (json.JSONDecodeError, OSError):
                pass
        # Infer from exploit_log.json
        if need:
            log_path = self.ws_path / "exploit_log.json"
            if log_path.is_file():
                try:
                    data = json.loads(log_path.read_text(encoding="utf-8"))
                    hash_accounts = {
                        str(h.get("account", "")).strip().lower()
                        for h in data.get("new_hashes") or []
                    }
                    for u in list(need):
                        if u in hash_accounts or u.rstrip("$") in hash_accounts:
                            self.progress.owned_methods[u] = "exploit_acl"
                            need.discard(u)
                except (json.JSONDecodeError, OSError):
                    pass
        # Default remaining to "password"
        for u in need:
            self.progress.owned_methods[u] = "password"

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
        """Hide full local paths and passwords from the dashboard terminal."""
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
            env=dashboard_subprocess_env(),
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
        if code == 0:
            self.emit("✓ Execution finished successfully", kind="done")
        else:
            self.emit(f"✗ Execution failed with exit code {code}", kind="error")
        return code

    def _persist_target_ip(self, ip: str) -> None:
        from admapper.cli.commands import dispatch
        from admapper.support.session import Session

        session = Session.bootstrap()
        session.select_workspace(self.workspace, create=True)
        dispatch(session, f"set hosts {ip}")
        session.persist_workspace()
        self.host = ip

    def run_scan(self, *, ip: str | None = None) -> bool:
        target = (ip or self._dc_ip()).strip()
        if not target:
            self.emit("sin IP — escribe la IP del objetivo en el terminal de arranque", kind="error")
            return False
        self._persist_target_ip(target)
        ok = self._run_workspace_script(
            "from admapper.cli.commands import dispatch\n"
            f"dispatch(session, 'set hosts {target}')\n"
            "dispatch(session, 'start_unauth')\n",
            label=f"scan {target}",
        )
        if ok:
            self.progress.scan = True
            self.progress.save(self.ws_path)
        return ok

    def run_auth(self, username: str, password: str, ip: str | None = None) -> None:
        target = (ip or self._dc_ip() or self.host or "").strip()
        if not target:
            self.emit("no IP — enter target IP before authenticating", kind="error")
            return
        if not username or not password:
            self.emit("user and password required", kind="error")
            return
        self._persist_target_ip(target)
        _server_log(f"[auth] target={target} user={username}")

        # Phase 02 — make sure we have discovered the domain / DC before verifying creds.
        if not self.domain:
            self.emit("discovering domain/DC before validating credentials", kind="phase")
            ok = self._run_workspace_script(
                "from admapper.cli.commands import dispatch\n"
                f"dispatch(session, 'set hosts {target}')\n"
                "dispatch(session, 'start_unauth')\n",
                label=f"scan {target}",
            )
            if not ok:
                self.emit("could not discover domain — run SCAN first", kind="error")
                return
            self.progress.scan = True
            self.progress.save(self.ws_path)
            self.domain = self._load_domain_from_state() or self.domain
            if not self.domain:
                self.emit("scan did not discover domain — verify VPN/target", kind="error")
                return

        auth_ok = self._run_workspace_script(
            "from admapper.dashboard.dashboard_auth import run_dashboard_credential_auth\n"
            f"run_dashboard_credential_auth(session, username={username!r}, password={password!r}, domain={self.domain!r})\n",
            label=f"authenticate as {username}",
        )
        if auth_ok:
            self.progress.remember_auth(username, method="password")
            self.pivot_user = username
            if self.ws_path.joinpath("graph.json").is_file():
                self._run_workspace_script(
                    "from admapper.escalate.analyze import mark_user_owned\n"
                    f"mark_user_owned(session, {username!r}, refresh=True)\n",
                    label=f"mark owned {username}",
                )
            self.progress.save(self.ws_path)

    def _run_workspace_script(self, script: str, *, label: str) -> bool:
        """Run in-process op with stdout routed through the dashboard terminal filter."""
        import io
        import traceback as _traceback
        from contextlib import redirect_stderr, redirect_stdout

        from admapper.support.session import Session

        self.emit(label, kind="cmd")
        self.terminal_filter.reset()
        session = Session.bootstrap()
        session.select_workspace(self.workspace, create=True)
        if session.workspace is not None:
            session.workspace.mode = OperationMode.AUTO
        _server_log(f"[run] workspace={self.workspace} label={label}")
        buf = io.StringIO()
        try:
            with redirect_stdout(buf), redirect_stderr(buf):
                exec(script, {"session": session, "__name__": "__main__"})  # noqa: S102
            session.persist_workspace()
            for line in buf.getvalue().splitlines():
                filtered = self.terminal_filter.process(line.rstrip())
                if filtered:
                    kind = "done" if filtered.startswith("✓") else "log"
                    self.emit(filtered, kind=kind)
            raw = buf.getvalue()
            if raw.strip():
                _server_log(f"[stdout/stderr] {label}\n{raw[:4000]}")
            _server_log(f"[done] {label} output_lines={len(raw.splitlines())}")
            self.emit("✓ Action completed successfully", kind="done")
            return True
        except Exception as exc:  # noqa: BLE001
            tb = _traceback.format_exc()
            _server_log(f"[error] {label}: {exc}\n{tb}")
            self.emit(str(exc), kind="error")
            self.emit("✗ Action failed", kind="error")
            return False

    def _get_stored_credential(self) -> tuple[str, str, str] | None:
        """Return (username, password, domain) from workspace credentials if available."""
        creds_path = self.ws_path / "credentials.json"
        if not creds_path.is_file():
            return None
        data = json.loads(creds_path.read_text(encoding="utf-8"))
        for c in data.get("credentials") or []:
            if str(c.get("status")) == "valid" and c.get("secret"):
                return (
                    str(c.get("username", "")),
                    str(c.get("secret", "")),
                    str(c.get("domain") or self.domain or ""),
                )
        return None

    def _load_domain_from_state(self) -> str | None:
        state_path = self.ws_path / "state.json"
        if state_path.is_file():
            data = json.loads(state_path.read_text(encoding="utf-8"))
            if data.get("domain"):
                return str(data["domain"])
        return None

    def _load_credentials(self) -> list[dict[str, Any]]:
        creds_path = self.ws_path / "credentials.json"
        if not creds_path.is_file():
            return []
        try:
            data = json.loads(creds_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return list(data.get("credentials") or [])

    def run_enum_users(self) -> None:
        from admapper.models.credential import CredentialStatus

        store = self._load_credentials()
        chosen = None
        for item in store:
            if item.get("status") != CredentialStatus.VALID.value:
                continue
            if not item.get("secret"):
                continue
            chosen = item
            pivot = (self.pivot_user or "").strip().lower()
            if pivot and str(item.get("username", "")).strip().lower() == pivot:
                break
        has_valid_cred = chosen is not None
        if has_valid_cred:
            display_user = str(chosen.get("username", "")).strip()
            display_domain = str(chosen.get("domain") or self.domain or "").strip()
            shown = f"{display_domain}\\{display_user}" if display_domain else display_user
            self.emit(f"authenticated LDAP/SMB enumeration as {shown}", kind="phase")
            ok = self._run_workspace_script(
                "from admapper.cli.commands import dispatch\n"
                f"dispatch(session, 'enum auth --cred-id {chosen.get('id')}')",
                label=f"enum auth {shown}",
            )
        else:
            self.emit("pre-auth user enumeration", kind="phase")
            ok = self._run_workspace_script(
                "from admapper.cli.commands import dispatch\n"
                "dispatch(session, 'enum users')",
                label="enum users",
            )
        if ok:
            self.progress.enum_users = True
            self.progress.save(self.ws_path)

    def run_asreproast(self) -> None:
        self._run_workspace_script(
            "from admapper.cli.commands import dispatch\n"
            "dispatch(session, 'asreproast')",
            label="asreproast",
        )
        self._sync_new_creds_owned(source="asreproast", method="asreproast")

    def run_kerberoast(self) -> None:
        self._run_workspace_script(
            "from admapper.cli.commands import dispatch\n"
            "dispatch(session, 'kerberoast')",
            label="kerberoast",
        )
        self._sync_new_creds_owned(source="kerberoast", method="kerberoast")

    def run_spray(self, password: str) -> None:
        if not password:
            self.emit("password required for spray", kind="error")
            return
        import base64

        pw_b64 = base64.b64encode(password.encode()).decode()
        ok = self._run_workspace_script(
            "import base64\n"
            "from admapper.cli.commands import dispatch\n"
            f"dispatch(session, 'spray ' + base64.b64decode('{pw_b64}').decode())",
            label="spray '***'",
        )
        if ok:
            self._sync_spray_owned()

    def run_exploit(self) -> None:
        ok = self._run_workspace_script(
            "from admapper.cli.commands import dispatch\n"
            "dispatch(session, 'exploit')",
            label="exploit (loot → ACL/gMSA)",
        )
        if ok:
            self.progress.exploit = True
            self._sync_exploit_owned()
            self.progress.save(self.ws_path)

    def run_acls(self) -> None:
        ok = self._run_workspace_script(
            "from admapper.cli.commands import dispatch\n"
            "dispatch(session, 'acls')",
            label="acl analysis",
        )
        if ok:
            self.progress.acls = True
            self.progress.save(self.ws_path)

    def set_pivot(self, username: str) -> None:
        if self.pivot_user and self.pivot_user.lower() == username.lower():
            return
        self._run_workspace_script(
            "from admapper.cli.commands import dispatch\n"
            f"dispatch(session, 'escalate pivot {username}')",
            label=f"pivot {username}",
        )
        self.pivot_user = username
        self.progress.remember_auth(username, method="password")
        self.progress.save(self.ws_path)

    def run_winrm_pth(self, account: str) -> None:
        ok = self._run_workspace_script(
            "from admapper.cli.commands import dispatch\n"
            f"dispatch(session, 'winrm {account}')",
            label=f"winrm PTH {account}",
        )
        if ok:
            self.pivot_user = account
            self.progress.remember_auth(account, method="ntlm_hash")
            self.progress.exploit = True
            # Mark the machine account as owned in the attack graph
            if self.ws_path.joinpath("graph.json").is_file():
                self._run_workspace_script(
                    "from admapper.escalate.analyze import mark_user_owned\n"
                    f"mark_user_owned(session, {account!r}, refresh=True)\n",
                    label=f"mark owned {account}",
                )
            if account.lower() not in {u.lower() for u in self.owned_users}:
                self.owned_users.append(account)
            if account.lower() not in {u.lower() for u in self.progress.owned_users}:
                self.progress.owned_users.append(account)
            self.progress.save(self.ws_path)

    def run_brief(self, *, auto: bool = False) -> None:
        self._run_workspace_script(
            "from admapper.cli.commands import dispatch\n"
            f"dispatch(session, 'brief {'auto' if auto else ''}'.strip())",
            label="brief",
        )


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


def make_handler(ctx: DashboardContext) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "ADMapper/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _start_background(self, fn: Callable[[], None]) -> None:
            if ctx.running:
                _json_response(self, 409, {"error": "operation in progress"})
                return
            if not ctx.op_lock.acquire(blocking=False):
                _json_response(self, 409, {"error": "operation in progress"})
                return

            def wrapper() -> None:
                ctx.running = True
                ctx.emit("─── operation start ───", kind="phase")
                try:
                    fn()
                    refresh_workspace_intel(ctx.ws_path)
                    ctx.emit("─── operation finished ───", kind="phase")
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
            if path in {"/", "/index.html", "/dashboard"}:
                html_content = build_dashboard_html(
                    ctx.ws_path,
                    workspace=ctx.workspace,
                    domain=ctx.domain,
                    owned_users=ctx.owned_users,
                    pivot_user=ctx.pivot_user,
                    api_mode=True,
                )
                body = html_content.encode("utf-8")
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
                ip = str(body.get("host") or body.get("ip") or body.get("ip_dc") or "").strip()
                self._start_background(lambda: ctx.run_scan(ip=ip or None))
                return

            if path == "/api/run":
                self._start_background(
                    lambda: ctx.run_auth(
                        str(body.get("username") or body.get("user") or body.get("u") or "").strip(),
                        str(body.get("password") or body.get("p") or ""),
                        str(body.get("host") or body.get("ip") or "").strip() or None,
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
                user = str(body.get("user") or body.get("username") or "").strip()
                if not user:
                    _json_response(self, 400, {"error": "username/user required"})
                    return
                try:
                    ctx.set_pivot(user)
                except (ValueError, RuntimeError) as exc:
                    _json_response(self, 400, {"error": str(exc)})
                    return
                payload = ctx.refresh_payload()
                _json_response(self, 200, {"ok": True, "pivot": user, "state": payload})
                return

            if path == "/api/winrm":
                account = str(body.get("account") or body.get("user") or body.get("username") or "").strip()
                if not account:
                    _json_response(self, 400, {"error": "account/user required"})
                    return
                self._start_background(lambda: ctx.run_winrm_pth(account))
                return

            if path == "/api/enum":
                if str(body.get("mode", "")).strip().lower() == "auth":
                    if not ctx._get_stored_credential():
                        _json_response(self, 400, {"error": "valid credential required"})
                        return
                    self._start_background(
                        lambda: ctx._run_workspace_script(
                            "from admapper.auth.start_auth import run_start_auth\n"
                            "run_start_auth(session)\n",
                            label="authenticated enum",
                        )
                    )
                    return
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

    return DashboardHandler


def run_dashboard_server(
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
    """Start blocking dashboard server until KeyboardInterrupt."""
    import webbrowser

    enable_dashboard_mode()
    refresh_workspace_intel(ws_path)
    ctx = DashboardContext(
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

        def handle_error(self, request: Any, client_address: tuple[str, int]) -> None:
            exc_type, exc, _ = sys.exc_info()
            if exc_type and issubclass(exc_type, (BrokenPipeError, ConnectionResetError, OSError)):
                return
            super().handle_error(request, client_address)

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
        raise OSError(f"puertos {port}–{port + 9} ocupados — cierra otra instancia de admapper dashboard")

    url = f"http://127.0.0.1:{bound_port}/"
    from admapper.support.output import print_info, print_success

    print_success(f"ADMapper dashboard → {url}")
    print_info("Ctrl+C para detener el servidor")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
