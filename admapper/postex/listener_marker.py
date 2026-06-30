"""Workspace listener.json marker — coordinates postex run and postex shell."""

from __future__ import annotations

import json
import socket
import time
from typing import TYPE_CHECKING

from admapper.support.output import print_warning

if TYPE_CHECKING:
    from admapper.support.session import Session

_DEFAULT_TTL_SECONDS = 3600


def marker_path(session: Session):
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    return session.workspaces.path_for(session.workspace.name) / "listener.json"


def _listener_ttl_seconds(session: Session) -> int:
    if session.workspace is None:
        return _DEFAULT_TTL_SECONDS
    config_path = session.workspaces.path_for(session.workspace.name) / "config.json"
    if not config_path.is_file():
        return _DEFAULT_TTL_SECONDS
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
        raw = (
            data.get("listener_ttl_seconds", _DEFAULT_TTL_SECONDS)
            if isinstance(data, dict)
            else _DEFAULT_TTL_SECONDS
        )
        ttl = int(raw)
    except (TypeError, ValueError, json.JSONDecodeError, OSError):
        return _DEFAULT_TTL_SECONDS
    return ttl if ttl > 0 else _DEFAULT_TTL_SECONDS


def is_port_in_use(port: int, *, bind_host: str = "0.0.0.0") -> bool:
    """Return True if another process is already bound to ``port``."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((bind_host, port))
        return False
    except OSError:
        return True
    finally:
        try:
            probe.close()
        except OSError:
            pass


def write_listener_marker(
    session: Session,
    *,
    port: int,
    op_id: str = "",
    connected: bool = False,
    peer: str = "",
) -> None:
    """Persist listener state so ``postex shell`` can avoid double-binding."""
    if session.workspace is None:
        return
    payload = {
        "port": port,
        "timestamp": time.time(),
        "op_id": op_id,
        "connected": connected,
        "peer": peer,
    }
    marker_path(session).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def update_listener_connected(
    session: Session,
    *,
    port: int,
    peer: str,
    op_id: str | None = None,
) -> None:
    """Update marker after a reverse shell callback is captured."""
    existing = read_listener_marker(session) or {}
    write_listener_marker(
        session,
        port=port,
        op_id=op_id if op_id is not None else str(existing.get("op_id") or ""),
        connected=True,
        peer=peer,
    )


def read_listener_marker(session: Session) -> dict | None:
    """Load a fresh listener marker or None if missing/expired."""
    if session.workspace is None:
        return None
    path = marker_path(session)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    ttl = _listener_ttl_seconds(session)
    timestamp = float(data.get("timestamp", 0))
    if time.time() - timestamp > ttl:
        expired_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp + ttl))
        print_warning(f"listener.json expired at {expired_at} — starting fresh listener")
        return None
    return data


def clear_listener_marker(session: Session) -> None:
    if session.workspace is None:
        return
    path = marker_path(session)
    if path.is_file():
        path.unlink()
