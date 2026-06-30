"""Interactive AD Ops dashboard HTTP server (stdlib only).

Serves the dashboard SPA and drives real admapper CLI phases from the browser.
Patterns implemented (see ops_ui.py header comment): mission briefing, animated
terminal via SSE, phase-gated actions, live graph refresh after each op.
"""

from __future__ import annotations

import errno
import json
import queue
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from admapper.models.workspace import OperationMode
from admapper.support.dashboard_mode import dashboard_subprocess_env, enable_dashboard_mode


def _server_log(msg: str) -> None:
    """Append a timestamped line to the server debug log."""
    try:
        with Path("/tmp/admapper_server.log").open("a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except OSError:
        pass


from admapper.dashboard.dashboard_html import build_dashboard_html
from admapper.dashboard.cli_launch import (
    build_blank_dashboard_payload,
    seed_workspace_from_vars,
    workspace_readiness,
)
from admapper.dashboard.target_ip import first_host_token
from admapper.dashboard.exec_bridge import (
    load_findings_notes,
    prepare_exec_request,
    save_cheatsheet_var_overrides,
    save_findings_notes,
)
from admapper.dashboard.ops_progress import OpsProgress
from admapper.dashboard.ops_ui import build_ops_payload
from admapper.dashboard.terminal_filter import TerminalFilter
from admapper.intelligence.user_match import refresh_workspace_intel


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
        ws_path: Path | None,
        workspace: str | None,
        domain: str | None,
        owned_users: list[str],
        pivot_user: str | None,
        host: str | None,
        pending_dc_ip: str | None = None,
    ) -> None:
        self.ws_path = ws_path
        self.workspace = workspace
        self.domain = domain
        self.owned_users = list(owned_users)
        self._initial_owned_users = list(owned_users)
        self.pivot_user = pivot_user
        self.host = host
        self.pending_dc_ip = pending_dc_ip
        self.events: queue.Queue[dict[str, Any]] = queue.Queue()
        self.op_lock = threading.Lock()
        self.running = False
        self.terminal_filter = TerminalFilter()
        self._shell_session = None
        if ws_path is not None:
            saved = OpsProgress.load(self.ws_path)
            if saved.scan or saved.enum_users:
                self.progress = saved
            else:
                self.progress = OpsProgress.fresh()
                self.progress.save(self.ws_path)
        else:
            self.progress = OpsProgress.fresh()

    @property
    def has_workspace(self) -> bool:
        return self.ws_path is not None and bool(self.workspace)

    def _require_workspace(self, *, label: str = "operation") -> bool:
        if self.has_workspace:
            return True
        self.emit(f"No workspace — create or open one in the header to run {label}", kind="error")
        return False

    def attach_workspace(
        self,
        name: str,
        *,
        create: bool = False,
        dc_ip: str | None = None,
    ) -> None:
        """Bind server context to a workspace (create, open, or after rename)."""
        from admapper.support.session import Session

        session = Session.bootstrap(autoload_workspace=False)
        session.select_workspace(name, create=create)
        ws = session.workspace
        if ws is None:
            raise RuntimeError("failed to attach workspace")

        self.workspace = ws.name
        self.ws_path = session.workspaces.path_for(ws.name)
        self.domain = ws.domain or None
        self.host = first_host_token(ws.hosts) or None
        self.pivot_user = ws.pivot_user or None
        self.owned_users = list(ws.owned_users or [])
        self._initial_owned_users = list(self.owned_users)
        self.pending_dc_ip = None

        saved = OpsProgress.load(self.ws_path)
        if saved.scan or saved.enum_users:
            self.progress = saved
        else:
            self.progress = OpsProgress.fresh()
            self.progress.save(self.ws_path)

        if dc_ip:
            dc_token = first_host_token(dc_ip)
            vars_out = seed_workspace_from_vars(
                session,
                {"DC_IP": dc_token},
                source="dashboard_ui",
            )
            self.host = dc_token
            hosts_msg = vars_out.pop("_hosts_message", None)
            if hosts_msg:
                kind = "done" if hosts_msg.startswith("/etc/hosts OK") else "info"
                self.emit(str(hosts_msg), kind=kind)

        refresh_workspace_intel(self.ws_path)

    def rename_workspace(self, new_name: str) -> None:
        if not self.has_workspace or self.workspace is None:
            raise RuntimeError("no active workspace")
        from admapper.support.config import load_config, save_config
        from admapper.support.session import Session

        old_name = self.workspace
        session = Session.bootstrap(autoload_workspace=False)
        session.workspaces.rename(old_name, new_name)
        config = load_config()
        if config.active_workspace == old_name:
            config.active_workspace = new_name
            save_config(config)
        self.attach_workspace(new_name, create=False)

    def emit(self, line: str, *, kind: str = "log") -> None:
        self.events.put({"type": kind, "line": line, "ts": time.time()})

    def refresh_payload(self) -> dict[str, Any]:
        if not self.has_workspace or self.ws_path is None:
            from admapper.support.session import Session

            session = Session.bootstrap(autoload_workspace=False)
            payload = build_blank_dashboard_payload(
                session.workspaces,
                pending_dc_ip=self.pending_dc_ip,
            )
            payload["running"] = bool(self.running)
            payload["busy"] = bool(self.op_lock.locked())
            return payload

        self._sync_offline_cracked_hashes()
        refresh_workspace_intel(self.ws_path)
        self.progress = OpsProgress.load(self.ws_path)
        self.progress.hydrate_from_workspace(self.ws_path)
        self._sync_loot_progress()

        from admapper.support.owned import sanitize_owned_users

        # Scrub parser/typing artifacts from progress lists (e.g. "user / pass" partials).
        for attr in ("owned_users", "verified_users", "auth_users"):
            clean, _ = sanitize_owned_users(list(getattr(self.progress, attr)))
            setattr(self.progress, attr, clean)
        clean_methods = {}
        for user, method in self.progress.owned_methods.items():
            clean, _ = sanitize_owned_users([user])
            if clean:
                clean_methods[clean[0].lower()] = method
        self.progress.owned_methods = clean_methods

        # Sync verified/owned users into self.progress from state.json & credentials.json
        state_path = self.ws_path / "state.json"
        if state_path.is_file():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
                state_owned, removed = sanitize_owned_users(list(state.get("owned_users") or []))
                if removed:
                    state["owned_users"] = state_owned
                    state_path.write_text(
                        json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                    )
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
                        if username_s.lower() not in {
                            u.lower() for u in self.progress.verified_users
                        }:
                            self.progress.verified_users.append(username_s)
                        if username_s.lower() not in {u.lower() for u in self.progress.owned_users}:
                            self.progress.owned_users.append(username_s)
            except Exception:
                pass

        self.progress.save(self.ws_path)

        from admapper.support.session import Session

        session = Session.bootstrap(autoload_workspace=False)
        session.select_workspace(self.workspace, create=False)
        if session.workspace is not None:
            ws_clean, _ = sanitize_owned_users(list(session.workspace.owned_users or []))
            if ws_clean != list(session.workspace.owned_users or []):
                session.workspace.owned_users = ws_clean
                session.persist_workspace()

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
                            if self.pivot_user.lower() not in {u.lower() for u in self.owned_users}:
                                self.owned_users.append(self.pivot_user)
                            break
                except (json.JSONDecodeError, OSError):
                    pass

        if self.pivot_user and self.pivot_user.lower() not in {u.lower() for u in self.owned_users}:
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
        payload["shell"] = self._shell_live_status()
        return payload

    def _shell_live_status(self) -> dict[str, Any]:
        """Expose reverse-shell listener state for dashboard UI re-attach."""
        out: dict[str, Any] = {
            "connected": False,
            "attached": False,
            "lport": 0,
            "peer": "",
        }
        if self._shell_session is not None and self._shell_session.active:
            out["attached"] = True
            out["connected"] = True
            out["lport"] = self._shell_session.lport
            return out
        if self._shell_session is not None and self._shell_session.session_connected:
            out["connected"] = True
            out["lport"] = self._shell_session.lport
            return out
        if not self.workspace:
            return out
        from admapper.postex.listener_marker import read_listener_marker
        from admapper.postex.shell_client import get_active_listener
        from admapper.support.session import Session

        session = Session.bootstrap(autoload_workspace=False)
        session.select_workspace(self.workspace, create=False)
        if session.workspace is None:
            return out
        marker = read_listener_marker(session) or {}
        try:
            lport = int(marker.get("port") or 0)
        except (TypeError, ValueError):
            lport = 0
        if not lport:
            return out
        listener = get_active_listener(self.workspace, lport)
        if listener is not None and listener.capture.connected:
            out["connected"] = True
            out["lport"] = lport
            out["peer"] = str(listener.capture.peer or "")
            return out
        if marker.get("connected"):
            out["stale_marker"] = True
            out["lport"] = lport
            out["peer"] = str(marker.get("peer") or "")
        return out

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
        cracked_creds: dict[str, str] = {}  # username -> password
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

                creds_list.append(
                    {
                        "id": uuid.uuid4().hex[:12],
                        "username": uname,
                        "secret": pwd,
                        "type": "password",
                        "domain": self.domain,
                        "status": "valid",
                        "source": "cracked",
                    }
                )
                updated = True

        if updated:
            try:
                creds_path.write_text(
                    json.dumps(creds_data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
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
                from admapper.escalate.analyze import mark_user_owned
                from admapper.support.session import Session

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
        shown = self._compact_cmd(cmd)
        self.emit(f"[*] Running: {shown}", kind="phase")
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

    def _discovery_script(self, target: str) -> str:
        return (
            "from admapper.cli.scan import run_unauth_discovery\n"
            f"run_unauth_discovery(session, host={target!r}, sync_clock=False)\n"
        )

    def run_scan(self, *, ip: str | None = None) -> bool:
        if not self._require_workspace(label="Discovery"):
            return False
        target = (ip or self._dc_ip()).strip()
        if not target:
            self.emit("no target IP — set DC IP in the terminal bar or header", kind="error")
            return False
        self._persist_target_ip(target)
        ok = self._run_workspace_script(
            self._discovery_script(target),
            label=f"Discovery {target}",
            echo_running=False,
            emit_done=False,
        )
        if ok:
            self.progress.scan = True
            self.progress.save(self.ws_path)
            self.domain = self._load_domain_from_state() or self.domain
            self._sync_hosts_after_target_change(target)
        return ok

    def _sync_hosts_after_target_change(self, ip: str) -> None:
        from admapper.dashboard.target_ip import sync_dc_hosts_for_session
        from admapper.support.session import Session
        from admapper.support.system_hosts import HostsSyncStatus, format_hosts_sync_message

        if not self.has_workspace or not self.workspace:
            return
        session = Session.bootstrap(autoload_workspace=False)
        session.select_workspace(self.workspace, create=False)
        result = sync_dc_hosts_for_session(session, ip)
        if not result or result.status == HostsSyncStatus.SKIPPED:
            return
        msg = format_hosts_sync_message(result)
        kind = "done" if result.status == HostsSyncStatus.PRESENT else "info"
        self.emit(msg, kind=kind)

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
                self._discovery_script(target),
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

    def _run_workspace_script(
        self,
        script: str,
        *,
        label: str,
        echo_running: bool = True,
        emit_done: bool = True,
    ) -> bool:
        """Run in-process op with stdout/stderr streamed to the dashboard terminal."""
        import traceback as _traceback

        from admapper.dashboard.terminal_stream import DashboardStream
        from admapper.support.output import console
        from admapper.support.session import Session

        if echo_running:
            self.emit(f"[*] Running: {label}", kind="phase")
        self.terminal_filter.reset()
        session = Session.bootstrap()
        session.select_workspace(self.workspace, create=True)
        if session.workspace is not None:
            session.workspace.mode = OperationMode.AUTO
        _server_log(f"[run] workspace={self.workspace} label={label}")
        stream = DashboardStream(self)
        prev_console_file = console.file
        console.file = stream
        try:
            from contextlib import redirect_stderr, redirect_stdout

            with redirect_stdout(stream), redirect_stderr(stream):
                exec(script, {"session": session, "__name__": "__main__"})  # noqa: S102
            stream.flush()
            session.persist_workspace()
            _server_log(f"[done] {label}")
            if emit_done:
                self.emit("✓ Action completed successfully", kind="done")
            return True
        except Exception as exc:  # noqa: BLE001
            stream.flush()
            tb = _traceback.format_exc()
            _server_log(f"[error] {label}: {exc}\n{tb}")
            self.emit(str(exc), kind="error")
            self.emit("✗ Action failed", kind="error")
            return False
        finally:
            console.file = prev_console_file

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

    def import_parser_items(self, items: list[dict[str, Any]]) -> dict[str, int]:
        """Merge operator-selected parser extractions into workspace JSON stores."""
        from admapper.models.credential import CredentialType
        from admapper.models.user import UserRecord
        from admapper.stores.credentials import CredentialStore
        from admapper.stores.users import UsersStore
        from admapper.support.workspace import WorkspaceManager

        manager = WorkspaceManager(self.ws_path.parent)
        users_store = UsersStore(manager, self.workspace)
        creds_store = CredentialStore(manager, self.workspace)

        new_users: list[UserRecord] = []
        creds_added = 0

        for raw in items:
            kind = str(raw.get("kind") or "").strip().lower()
            username = str(raw.get("username") or "").strip()
            secret = str(raw.get("secret") or "").strip()
            domain = str(raw.get("domain") or self.domain or "").strip() or None

            if kind == "spn":
                spn = str(raw.get("spn") or secret).strip()
                if not spn:
                    continue
                user = username
                if not user and "/" in spn:
                    host_part = spn.split("/", 1)[1].split(":", 1)[0]
                    user = host_part.split(".", 1)[0]
                if user:
                    new_users.append(
                        UserRecord(
                            username=user,
                            sources=["output_parser"],
                            spns=[spn],
                            kerberoastable=True,
                        )
                    )
                continue

            if not secret:
                continue

            if kind == "password":
                if not username:
                    continue
                creds_store.add(
                    username,
                    secret,
                    domain=domain,
                    cred_type=CredentialType.PASSWORD,
                    source="output_parser",
                )
                creds_added += 1
                self.progress.remember_owned(username, method="output_parser")
                if username.lower() not in {u.lower() for u in self.owned_users}:
                    self.owned_users.append(username)
                continue

            if kind == "ntlm":
                if not username:
                    continue
                creds_store.add(
                    username,
                    secret,
                    domain=domain,
                    cred_type=CredentialType.NTLM,
                    source="output_parser",
                )
                creds_added += 1
                continue

            if kind in {"kerberos", "asrep", "tgs"}:
                if not username:
                    continue
                creds_store.add(
                    username,
                    secret,
                    domain=domain,
                    cred_type=CredentialType.KERBEROS,
                    source="output_parser",
                )
                creds_added += 1

        users_merged = 0
        if new_users:
            users_store.merge(new_users)
            users_merged = len(new_users)

        if creds_added:
            self.progress.save(self.ws_path)

        return {"credentials_added": creds_added, "users_merged": users_merged}

    def _chosen_valid_credential(self) -> dict | None:
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
        return chosen

    def run_enum_users(self) -> None:
        chosen = self._chosen_valid_credential()
        cred_id = str(chosen.get("id")) if chosen else None
        if chosen:
            display_user = str(chosen.get("username", "")).strip()
            display_domain = str(chosen.get("domain") or self.domain or "").strip()
            shown = f"{display_domain}\\{display_user}" if display_domain else display_user
            self.emit(f"authenticated LDAP/SMB enumeration as {shown}", kind="phase")
            label = f"enumerate users ({shown})"
        else:
            self.emit("pre-auth user enumeration", kind="phase")
            label = "enumerate users (pre-auth)"
        ok = self._run_workspace_script(
            "from admapper.enum.scan import run_domain_enumeration\n"
            f"run_domain_enumeration(session, cred_id={cred_id!r})\n",
            label=label,
        )
        if ok:
            self.progress.enum_users = True
            self.progress.save(self.ws_path)

    def run_asreproast(self) -> None:
        self._run_workspace_script(
            "from admapper.cli.commands import dispatch\ndispatch(session, 'asreproast')",
            label="asreproast",
        )
        self._sync_new_creds_owned(source="asreproast", method="asreproast")

    def run_kerberoast(self) -> None:
        self._run_workspace_script(
            "from admapper.cli.commands import dispatch\ndispatch(session, 'kerberoast')",
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
            "from admapper.cli.commands import dispatch\ndispatch(session, 'exploit')",
            label="exploit (loot → ACL/gMSA)",
        )
        if ok:
            self.progress.exploit = True
            self._sync_exploit_owned()
            self.progress.save(self.ws_path)

    def run_acls(self) -> None:
        chosen = self._chosen_valid_credential()
        cred_id = str(chosen.get("id")) if chosen else ""
        if cred_id:
            script = (
                "from admapper.cli.commands import dispatch\n"
                f"dispatch(session, 'acls --cred-id {cred_id}')",
            )
        else:
            script = "from admapper.cli.commands import dispatch\ndispatch(session, 'acls')"
        ok = self._run_workspace_script(
            script,
            label="acl analysis",
            echo_running=False,
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
            f"from admapper.cli.commands import dispatch\ndispatch(session, 'winrm {account}')",
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

    def run_postex(self, body: dict[str, Any]) -> None:
        """Deploy DLL hijack + reverse shell listener; stream output to dashboard terminal."""
        if not self._require_workspace(label="postex run"):
            return

        op_id = str(body.get("op") or body.get("op_id") or "").strip()
        if not op_id:
            self.emit("postex op id required", kind="error")
            self.emit("✗ Post-ex run failed", kind="error")
            return

        arch_raw = str(body.get("arch") or "").strip() or None
        try:
            lport = int(body.get("lport") or 443)
        except (TypeError, ValueError):
            lport = 443

        lhost = str(
            body.get("lhost") or body.get("LHOST") or body.get("ATTACKER_IP") or ""
        ).strip() or None

        if not lhost and self.ws_path is not None:
            from admapper.dashboard.exec_bridge import build_cheatsheet_vars

            cv = build_cheatsheet_vars(
                self.ws_path,
                workspace=self.workspace,
                domain=self.domain or "",
                pivot=self.pivot_user or "",
                dc_ip=self.host or "",
            )
            lhost = str(cv.get("LHOST") or cv.get("ATTACKER_IP") or "").strip() or None

        chosen = self._chosen_valid_credential()
        cred_id = str(body.get("cred_id") or (chosen.get("id") if chosen else "") or "").strip()
        cred_id = cred_id or None

        from admapper.dashboard.terminal_stream import DashboardStream
        from admapper.models.workspace import OperationMode
        from admapper.postex.pe_arch import normalize_arch
        from admapper.postex.runner import run_dll_hijack
        from admapper.support.output import console
        from admapper.support.session import Session

        payload_arch = normalize_arch(arch_raw) if arch_raw else None
        arch_suffix = f" --arch {arch_raw}" if arch_raw else ""
        label = f"postex run --op {op_id} --lport {lport}{arch_suffix}"

        self.emit(f"[*] Running: {label}", kind="phase")
        self.terminal_filter.reset()

        session = Session.bootstrap()
        session.select_workspace(self.workspace, create=True)
        if session.workspace is not None:
            session.workspace.mode = OperationMode.AUTO

        stream = DashboardStream(self)
        prev_console_file = console.file
        console.file = stream
        result = None
        try:
            from contextlib import redirect_stderr, redirect_stdout

            with redirect_stdout(stream), redirect_stderr(stream):
                result = run_dll_hijack(
                    session,
                    op_id=op_id,
                    cred_id=cred_id,
                    lhost=lhost,
                    lport=lport,
                    arch=payload_arch,
                    interactive=False,
                    auto_chain=False,
                    keep_listener=True,
                    max_wait_cycles=10,
                    auto_trigger_task=True,
                )
            stream.flush()
            session.persist_workspace()
            if result.shell_connected:
                self.progress.exploit = True
                self.progress.save(self.ws_path)
                self.emit("✓ Reverse shell callback received", kind="done")
                try:
                    from admapper.dashboard.shell_bridge import attach_shell

                    attach_shell(self, lport=lport, emit_ready=False)
                    self.emit(
                        json.dumps({"lport": lport, "attached": True}),
                        kind="shell_ready",
                    )
                    self.emit(json.dumps({"refresh": True}), kind="state")
                except Exception as exc:  # noqa: BLE001
                    self.emit(str(exc), kind="error")
                    self.emit(
                        json.dumps({"lport": lport, "attached": False}),
                        kind="shell_ready",
                    )
            else:
                self.emit("[!] No shell callback — review service log above", kind="warn")
                self.emit(
                    "[*] Tip: trigger the scheduled task from WinRM "
                    "(schtasks /run /tn StartupAppTask) or wait for the next run",
                    kind="info",
                )
                self.emit("✓ Post-ex deploy finished (no callback)", kind="done")
        except Exception as exc:  # noqa: BLE001
            stream.flush()
            self.emit(str(exc), kind="error")
            self.emit("✗ Post-ex run failed", kind="error")
        finally:
            console.file = prev_console_file

    def start_postex_shell(self, *, lport: int) -> None:
        if not self._require_workspace(label="postex shell"):
            return
        from admapper.dashboard.shell_bridge import attach_shell

        try:
            attach_shell(self, lport=lport)
            self.emit(f"[*] Interactive shell attached on port {lport}", kind="log")
        except Exception as exc:  # noqa: BLE001
            self.emit(str(exc), kind="error")

    def send_postex_shell(self, line: str) -> None:
        if self._shell_session is None or not self._shell_session.active:
            self.emit("no active shell session — attach first", kind="error")
            return
        try:
            self._shell_session.send(line)
        except Exception as exc:  # noqa: BLE001
            self.emit(str(exc), kind="error")
            self.stop_postex_shell()

    def stop_postex_shell(self) -> None:
        if self._shell_session is not None:
            self._shell_session.stop()
            self._shell_session = None
            self.emit("[*] Shell detached (listener may still be open)", kind="phase")

    def run_bloodhound_collect(self, *, collect: str = "All") -> None:
        """Trigger bloodhound-python collection and rebuild bloodhound_overlay.json."""
        if not self._get_stored_credential():
            self.emit("valid credential required for BloodHound collection", kind="error")
            self.emit("✗ Action failed", kind="error")
            return
        collect_s = (collect or "All").strip() or "All"
        self._run_workspace_script(
            "from admapper.auth.bloodhound_collect import run_bloodhound_collect\n"
            f"run_bloodhound_collect(session, collect={collect_s!r})\n",
            label=f"bloodhound-python ({collect_s})",
        )

    def run_sharphound_collect(self, body: dict[str, Any]) -> None:
        """Run bundled SharpHound on target (shell or WinRM) and import bloodhound overlay."""
        if not self._require_workspace(label="SharpHound collect"):
            return

        via = str(body.get("via") or "auto").strip().lower()
        lhost = str(body.get("lhost") or body.get("LHOST") or "").strip() or None
        cred_id = str(body.get("cred_id") or "").strip() or None

        from admapper.sharphound.runner import collect_sharphound
        from admapper.support.session import Session

        session = Session.bootstrap()
        session.select_workspace(self.workspace, create=True)

        shell = self._shell_session
        if via in {"auto", "shell"} and (shell is None or not shell.session_connected):
            from admapper.dashboard.shell_bridge import attach_shell
            from admapper.postex.listener_marker import read_listener_marker
            from admapper.postex.shell_client import get_active_listener

            marker = read_listener_marker(session) or {}
            try:
                lport = int(marker.get("port") or 443)
            except (TypeError, ValueError):
                lport = 443
            listener = get_active_listener(self.workspace or "", lport) if self.workspace else None
            if listener is not None and listener.capture.connected:
                try:
                    attach_shell(self, lport=lport, emit_ready=False)
                    shell = self._shell_session
                except Exception:
                    pass

        if via == "auto" and shell is not None and shell.session_connected:
            via = "shell"
        elif via == "auto":
            from admapper.postex.listener_marker import read_listener_marker

            _sess = Session.bootstrap(autoload_workspace=False)
            _sess.select_workspace(self.workspace or "", create=False)
            _marker = read_listener_marker(_sess) if _sess.workspace else {}
            msg = (
                "active reverse shell required — run Establish Reverse Shell "
                "from this dashboard session first"
            )
            if _marker.get("connected"):
                msg = (
                    "shell session ended (stale) — re-run Establish Reverse Shell, "
                    "then retry SH Collect"
                )
            self.emit(msg, kind="error")
            self.emit("✗ SharpHound collect failed", kind="error")
            return
        if via == "shell" and (shell is None or not shell.session_connected):
            self.emit(
                "active reverse shell required — run Establish Reverse Shell "
                "from this dashboard session first",
                kind="error",
            )
            self.emit("✗ SharpHound collect failed", kind="error")
            return

        self.emit(f"[*] SharpHound collect (via={via})…", kind="phase")
        from admapper.dashboard.terminal_stream import DashboardStream
        from admapper.support.output import console

        stream = DashboardStream(self)
        prev_console_file = console.file
        console.file = stream
        result = None
        try:
            from contextlib import redirect_stderr, redirect_stdout

            with redirect_stdout(stream), redirect_stderr(stream):
                result = collect_sharphound(
                    session,
                    via=via,
                    shell=shell,
                    cred_id=cred_id or None,
                    lhost=lhost,
                )
            stream.flush()
            session.persist_workspace()
            if result is not None:
                pivot = (
                    session.workspace.pivot_user if session.workspace else self.pivot_user or ""
                )
                self.emit(
                    f"✓ SharpHound imported — overlay + attack vector updated"
                    + (f" (pivot {pivot})" if pivot else f" ({result.name})"),
                    kind="done",
                )
            else:
                self.emit("✓ SharpHound collect finished", kind="done")
            self.emit(json.dumps({"refresh": True}), kind="state")
        except Exception as exc:  # noqa: BLE001
            stream.flush()
            self.emit(str(exc), kind="error")
            self.emit("✗ SharpHound collect failed", kind="error")
        finally:
            console.file = prev_console_file

    def run_exec(self, body: dict[str, Any]) -> None:
        """Run an arbitrary admapper/external CLI from a command template + workspace vars."""
        from admapper.support.session import Session

        session = Session.bootstrap()
        session.select_workspace(self.workspace, create=True)
        try:
            argv, resolved = prepare_exec_request(body, session)
        except ValueError as exc:
            self.emit(str(exc), kind="error")
            self.emit("✗ Execution rejected", kind="error")
            return
        self.emit(resolved, kind="phase")
        self._run_subprocess(argv)

    def seed_workspace_vars(self, raw: dict[str, Any], *, verify_cred: bool = False) -> dict[str, str]:
        """Apply UI/CLI operator vars to workspace + cheatsheet_vars."""
        if not self._require_workspace(label="var updates"):
            return {}

        from admapper.support.session import Session

        session = Session.bootstrap(autoload_workspace=False)
        session.select_workspace(self.workspace, create=False)
        merged = dict(raw.get("workspace_vars") or {})
        merged.update({k: v for k, v in raw.items() if k not in {"workspace_vars", "vars"}})
        vars_out = seed_workspace_from_vars(
            session,
            merged,
            source="dashboard_ui",
            verify_cred=verify_cred,
        )
        hosts_msg = vars_out.pop("_hosts_message", None)
        if hosts_msg:
            kind = "done" if str(hosts_msg).startswith("/etc/hosts OK") else "info"
            self.emit(str(hosts_msg), kind=kind)
        ws = session.workspace
        if ws is not None:
            if ws.domain:
                self.domain = ws.domain
            if ws.hosts:
                self.host = ws.hosts.split()[0]
            if ws.pivot_user:
                self.pivot_user = ws.pivot_user
            merged_owned = set(self.owned_users or [])
            for u in ws.owned_users or []:
                merged_owned.add(u)
            self.owned_users = sorted(merged_owned, key=str.lower)
        return vars_out

    def connect_workspace(self, body: dict[str, Any]) -> None:
        """Seed vars from UI then run LDAP/SMB credential verification."""
        if not self._require_workspace(label="authentication"):
            return
        username = str(
            body.get("username") or body.get("user") or body.get("USERNAME") or ""
        ).strip()
        password = str(body.get("password") or body.get("PASSWORD") or body.get("p") or "")
        nthash = str(body.get("NTLM_HASH") or body.get("nthash") or body.get("hash") or "")
        ip = str(
            body.get("host")
            or body.get("ip")
            or body.get("DC_IP")
            or body.get("dc_ip")
            or ""
        ).strip() or None

        self.seed_workspace_vars(body)
        if username and password:
            self.run_auth(username, password, ip)
            return
        if username and nthash:
            self.emit(
                "NTLM hash saved — use WinRM PTH or cheatsheet commands; password auth skipped",
                kind="info",
            )
            return
            self.emit("workspace vars saved — add password or hash to authenticate", kind="log")


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
            if ctx._shell_session is not None and ctx._shell_session._command_batch_depth > 0:
                _json_response(self, 409, {"error": "shell busy — wait for collect to finish"})
                return
            if not ctx.op_lock.acquire(blocking=False):
                _json_response(self, 409, {"error": "operation in progress"})
                return

            def wrapper() -> None:
                ctx.running = True
                try:
                    fn()
                    refresh_workspace_intel(ctx.ws_path)
                    ctx.emit(json.dumps({"refresh": True}), kind="state")
                except Exception as exc:  # noqa: BLE001 — surface to terminal UI
                    ctx.emit(f"[!] {exc}", kind="error")
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
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/api/state":
                payload = ctx.refresh_payload()
                _json_response(self, 200, payload)
                return

            if path == "/api/workspaces":
                from admapper.support.session import Session

                session = Session.bootstrap(autoload_workspace=False)
                _json_response(
                    self,
                    200,
                    {"workspaces": session.workspaces.list_workspaces()},
                )
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
                if not ctx.has_workspace:
                    _json_response(self, 400, {"error": "workspace required"})
                    return
                ip = str(body.get("host") or body.get("ip") or body.get("ip_dc") or body.get("DC_IP") or "").strip()
                if ip:
                    ctx.seed_workspace_vars({"DC_IP": ip, "host": ip})

                def _scan() -> None:
                    ctx.run_scan(ip=ip or None)

                self._start_background(_scan)
                return

            if path == "/api/run":
                def _auth_from_ui() -> None:
                    ctx.connect_workspace(body)

                self._start_background(_auth_from_ui)
                return

            if path == "/api/workspace/seed":
                if not ctx.has_workspace:
                    _json_response(self, 400, {"error": "workspace required"})
                    return
                try:
                    ctx.seed_workspace_vars(body)
                except (ValueError, OSError) as exc:
                    _json_response(self, 400, {"error": str(exc)})
                    return
                payload = ctx.refresh_payload()
                _json_response(self, 200, {"ok": True, "state": payload})
                return

            if path == "/api/workspace/create":
                name = str(body.get("name") or "").strip()
                if not name:
                    _json_response(self, 400, {"error": "name required"})
                    return
                dc_ip = str(body.get("dc_ip") or body.get("DC_IP") or "").strip() or None
                try:
                    ctx.attach_workspace(name, create=True, dc_ip=dc_ip)
                except (ValueError, FileNotFoundError, OSError) as exc:
                    _json_response(self, 400, {"error": str(exc)})
                    return
                payload = ctx.refresh_payload()
                _json_response(self, 200, {"ok": True, "workspace": name, "state": payload})
                return

            if path == "/api/workspace/open":
                name = str(body.get("name") or "").strip()
                if not name:
                    _json_response(self, 400, {"error": "name required"})
                    return
                try:
                    ctx.attach_workspace(name, create=False)
                except (ValueError, FileNotFoundError, OSError) as exc:
                    _json_response(self, 400, {"error": str(exc)})
                    return
                payload = ctx.refresh_payload()
                _json_response(self, 200, {"ok": True, "workspace": name, "state": payload})
                return

            if path == "/api/workspace/rename":
                if not ctx.has_workspace:
                    _json_response(self, 400, {"error": "workspace required"})
                    return
                name = str(body.get("name") or "").strip()
                if not name:
                    _json_response(self, 400, {"error": "name required"})
                    return
                try:
                    ctx.rename_workspace(name)
                except (ValueError, FileNotFoundError, OSError) as exc:
                    _json_response(self, 400, {"error": str(exc)})
                    return
                payload = ctx.refresh_payload()
                _json_response(self, 200, {"ok": True, "workspace": name, "state": payload})
                return

            if path == "/api/workspace/connect":
                def _connect() -> None:
                    ctx.connect_workspace(body)

                self._start_background(_connect)
                return

            if path == "/api/exploit":
                self._start_background(ctx.run_exploit)
                return

            if path == "/api/postex/run":
                if not ctx.has_workspace:
                    _json_response(self, 400, {"error": "workspace required"})
                    return
                op = str(body.get("op") or body.get("op_id") or "").strip()
                if not op:
                    _json_response(self, 400, {"error": "op required"})
                    return
                self._start_background(lambda: ctx.run_postex(body))
                return

            if path == "/api/postex/shell/start":
                if not ctx.has_workspace:
                    _json_response(self, 400, {"error": "workspace required"})
                    return
                if ctx._shell_session is not None and ctx._shell_session._command_batch_depth > 0:
                    _json_response(self, 409, {"error": "shell busy — wait for collect to finish"})
                    return
                try:
                    lport = int(body.get("lport") or 443)
                except (TypeError, ValueError):
                    lport = 443
                try:
                    ctx.start_postex_shell(lport=lport)
                except Exception as exc:  # noqa: BLE001
                    _json_response(self, 400, {"error": str(exc)})
                    return
                _json_response(self, 200, {"ok": True, "lport": lport})
                return

            if path == "/api/postex/shell/send":
                line = str(body.get("line") or body.get("command") or "")
                if not line.strip():
                    _json_response(self, 400, {"error": "line required"})
                    return
                ctx.send_postex_shell(line)
                _json_response(self, 200, {"ok": True})
                return

            if path == "/api/postex/shell/stop":
                ctx.stop_postex_shell()
                _json_response(self, 200, {"ok": True})
                return

            if path == "/api/acls":
                self._start_background(ctx.run_acls)
                return

            if path == "/api/brief":
                auto = bool(body.get("auto", False))
                self._start_background(lambda: ctx.run_brief(auto=auto))
                return

            if path == "/api/bloodhound":
                collect = str(body.get("collect") or "All").strip() or "All"
                self._start_background(lambda: ctx.run_bloodhound_collect(collect=collect))
                return

            if path == "/api/sharphound/collect":
                if not ctx.has_workspace:
                    _json_response(self, 400, {"error": "workspace required"})
                    return
                self._start_background(lambda: ctx.run_sharphound_collect(body))
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
                account = str(
                    body.get("account") or body.get("user") or body.get("username") or ""
                ).strip()
                if not account:
                    _json_response(self, 400, {"error": "account/user required"})
                    return
                self._start_background(lambda: ctx.run_winrm_pth(account))
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

            if path == "/api/import":
                raw_items = body.get("items")
                if not isinstance(raw_items, list) or not raw_items:
                    _json_response(self, 400, {"error": "items array required"})
                    return
                try:
                    counts = ctx.import_parser_items(raw_items)
                except (ValueError, OSError) as exc:
                    _json_response(self, 400, {"error": str(exc)})
                    return
                payload = ctx.refresh_payload()
                _json_response(
                    self,
                    200,
                    {"ok": True, **counts, "state": payload},
                )
                return

            if path == "/api/exec":
                if not body.get("command_template") and not body.get("command"):
                    _json_response(self, 400, {"error": "command_template required"})
                    return
                self._start_background(lambda: ctx.run_exec(body))
                return

            if path == "/api/cheatsheet-vars":
                updates = body.get("vars") if isinstance(body.get("vars"), dict) else body
                try:
                    ctx.seed_workspace_vars({"workspace_vars": updates, **updates})
                except (ValueError, OSError) as exc:
                    _json_response(self, 400, {"error": str(exc)})
                    return
                payload = ctx.refresh_payload()
                _json_response(self, 200, {"ok": True, "state": payload})
                return

            if path == "/api/notes":
                raw_notes = body.get("notes")
                if raw_notes is not None:
                    if not isinstance(raw_notes, list):
                        _json_response(self, 400, {"error": "notes must be an array"})
                        return
                    try:
                        save_findings_notes(ctx.ws_path, raw_notes)
                    except OSError as exc:
                        _json_response(self, 400, {"error": str(exc)})
                        return
                elif body.get("note"):
                    note = body.get("note")
                    if not isinstance(note, dict):
                        _json_response(self, 400, {"error": "note object required"})
                        return
                    current = load_findings_notes(ctx.ws_path)
                    current.append(note)
                    try:
                        save_findings_notes(ctx.ws_path, current)
                    except OSError as exc:
                        _json_response(self, 400, {"error": str(exc)})
                        return
                else:
                    _json_response(self, 400, {"error": "notes array or note object required"})
                    return
                payload = ctx.refresh_payload()
                _json_response(self, 200, {"ok": True, "state": payload})
                return

            self.send_error(404)

    return DashboardHandler


def run_dashboard_server(
    *,
    ws_path: Path | None,
    workspace: str | None,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
    host: str | None = None,
    pending_dc_ip: str | None = None,
    port: int = 8766,
    open_browser: bool = True,
) -> None:
    """Start blocking dashboard server until KeyboardInterrupt."""
    import webbrowser

    enable_dashboard_mode()
    if ws_path is not None:
        refresh_workspace_intel(ws_path)
    ctx = DashboardContext(
        ws_path=ws_path,
        workspace=workspace,
        domain=domain,
        owned_users=list(owned_users or []),
        pivot_user=pivot_user,
        host=host,
        pending_dc_ip=pending_dc_ip,
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
        raise OSError(
            f"puertos {port}–{port + 9} ocupados — cierra otra instancia de admapper dashboard"
        )

    url = f"http://127.0.0.1:{bound_port}/"
    from admapper.support.output import print_info, print_success

    print_success(f"ADMapper dashboard → {url}")
    if not workspace:
        print_info("No workspace loaded — create or open one in the dashboard")
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
