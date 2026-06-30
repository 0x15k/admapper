"""Stream in-process dashboard script stdout/stderr to the SSE terminal."""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from admapper.dashboard.dashboard_server import DashboardContext


class DashboardStream(io.TextIOBase):
    """Line-buffered writer that emits filtered CLI output as SSE events."""

    def __init__(self, ctx: DashboardContext) -> None:
        self._ctx = ctx
        self._filter = ctx.terminal_filter
        self._buf = ""

    def write(self, s: str) -> int:  # type: ignore[override]
        if not s:
            return 0
        self._buf += s.replace("\r\n", "\n").replace("\r", "\n")
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._emit_line(line)
        return len(s)

    def flush(self) -> None:
        if self._buf.strip():
            self._emit_line(self._buf)
            self._buf = ""

    def isatty(self) -> bool:
        return False

    def _emit_line(self, line: str) -> None:
        filtered = self._filter.process(line.rstrip())
        if not filtered:
            return
        kind = "log"
        stripped = filtered.lstrip()
        if stripped.startswith("✓") or (
            stripped.startswith("[+]") and "recon complete" in stripped.lower()
        ):
            kind = "done"
        elif stripped.startswith("!") or stripped.startswith("✗") or stripped.startswith("[-]"):
            kind = "error"
        elif stripped.startswith("→") or stripped.startswith("──") or stripped.startswith("[*]"):
            kind = "phase"
        self._ctx.emit(filtered, kind=kind)
