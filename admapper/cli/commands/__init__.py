from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

from admapper.cli.commands import creds, escalate, graph, meta, modules, postex, recon
from admapper.core.output import print_error

if TYPE_CHECKING:
    from admapper.core.session import Session

_HANDLERS = (
    meta.handle,
    creds.handle,
    recon.handle,
    graph.handle,
    modules.handle,
    postex.handle,
    escalate.handle,
)


def dispatch(session: Session, line: str) -> bool:
    """Execute one shell line. Returns False when the shell should exit."""
    stripped = line.strip()
    if not stripped:
        return True

    try:
        parts = shlex.split(stripped)
    except ValueError as exc:
        print_error(f"invalid command quoting: {exc}")
        return True

    cmd = parts[0].lower()
    args = parts[1:]

    for handler in _HANDLERS:
        result = handler(session, cmd, args)
        if result is not None:
            return result

    print_error(f"unknown command: {cmd} — type 'help'")
    return True


__all__ = ["dispatch"]
