"""Bridge reverse-shell TCP I/O to dashboard SSE (interactive shell in the web UI)."""

from __future__ import annotations

import json
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from admapper.dashboard.dashboard_server import DashboardContext
    from admapper.postex.listener import ReverseShellListener


class DashboardShellSession:
    """Pump reverse-shell socket bytes to SSE; accept commands from the UI."""

    def __init__(
        self,
        ctx: DashboardContext,
        listener: ReverseShellListener,
        *,
        lport: int,
    ) -> None:
        self._ctx = ctx
        self._listener = listener
        self.lport = lport
        self._stop = threading.Event()
        self._detached = False
        self._thread: threading.Thread | None = None
        self._command_batch_depth = 0

    @property
    def active(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def session_connected(self) -> bool:
        return (
            not self._detached
            and self._listener.capture.connected
            and self._listener._conn is not None
        )

    def start(self, *, emit_ready: bool = True) -> None:
        if not self._listener.capture.connected or self._listener._conn is None:
            raise RuntimeError("no active reverse shell connection")
        if self.active:
            return
        self._detached = False
        self._listener.begin_interact()
        self._stop.clear()
        self._thread = threading.Thread(target=self._pump, name="dashboard-shell-pump", daemon=True)
        self._thread.start()
        if emit_ready:
            peer = self._listener.capture.peer or "target"
            self._ctx.emit(
                json.dumps({"lport": self.lport, "peer": peer, "attached": True}),
                kind="shell_ready",
            )

    def _pump(self) -> None:
        conn = self._listener._conn
        if conn is None:
            return
        try:
            while not self._stop.is_set():
                if not self._listener._io_lock.acquire(timeout=0.05):
                    continue
                try:
                    if self._stop.is_set():
                        break
                    conn.settimeout(0.25)
                    data = conn.recv(4096)
                except TimeoutError:
                    continue
                except OSError:
                    break
                finally:
                    self._listener._io_lock.release()
                if not data:
                    break
                if self._stop.is_set():
                    break
                self._ctx.emit(data.decode("utf-8", errors="replace"), kind="shell")
        finally:
            if not self._stop.is_set():
                self._ctx.emit("[shell disconnected]", kind="shell")
                self._ctx.emit(json.dumps({"lport": self.lport}), kind="shell_stopped")

    def send(self, line: str) -> None:
        if not line.strip():
            return
        self._listener.send_raw(line)

    def _pause_pump(self) -> None:
        self._stop.set()
        try:
            self._listener.end_interact()
        except Exception:
            pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=8.0)
        self._thread = None
        try:
            self._listener._drain_socket(timeout=0.3)
        except Exception:
            pass

    def _resume_pump(self) -> None:
        if self._detached or self.active:
            return
        if not self._listener.capture.connected or self._listener._conn is None:
            return
        self._listener.begin_interact()
        self._stop.clear()
        self._thread = threading.Thread(target=self._pump, name="dashboard-shell-pump", daemon=True)
        self._thread.start()

    def command_batch(self):
        """Keep the SSE pump paused across multiple synchronous shell commands."""
        shell = self

        class _Batch:
            def __enter__(self) -> _Batch:
                shell._command_batch_depth += 1
                if shell._command_batch_depth == 1:
                    shell._pause_pump()
                return self

            def __exit__(self, *exc: object) -> None:
                shell._command_batch_depth = max(0, shell._command_batch_depth - 1)
                if shell._command_batch_depth == 0 and not shell._detached:
                    shell._resume_pump()

        return _Batch()

    def probe(self, *, timeout: float = 10.0) -> bool:
        """Quick echo check that the shell answers synchronous commands."""
        try:
            out = self.run_command("echo ADMAPPER_PING", timeout=timeout)
            return "ADMAPPER_PING" in out
        except Exception:
            return False

    def run_command(self, line: str, *, timeout: float = 120.0) -> str:
        """Run one synchronous command (pauses SSE pump while waiting for output)."""
        nested = self._command_batch_depth > 0
        if not nested:
            self._pause_pump()
        else:
            try:
                self._listener.end_interact()
            except Exception:
                pass
            try:
                self._listener._drain_socket(timeout=0.15)
            except Exception:
                pass
        try:
            return self._listener.send(line, timeout=timeout)
        finally:
            if not nested and not self._detached:
                self._resume_pump()

    def stop(self) -> None:
        self._detached = True
        self._stop.set()
        try:
            self._listener.end_interact()
        except Exception:
            pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None
        self._ctx.emit(json.dumps({"lport": self.lport}), kind="shell_stopped")


def attach_shell(ctx: DashboardContext, *, lport: int, emit_ready: bool = True) -> None:
    """Attach UI to the in-process listener from a dashboard postex run."""
    from admapper.postex.shell_client import get_active_listener

    if ctx.workspace is None:
        raise RuntimeError("no active workspace")
    if ctx._shell_session is not None:
        if ctx._shell_session._command_batch_depth > 0:
            raise RuntimeError("shell busy — wait for the current collect/operation to finish")
        if (
            ctx._shell_session.active
            and ctx._shell_session.session_connected
            and ctx._shell_session.lport == lport
        ):
            return
        if ctx._shell_session.active:
            ctx._shell_session.stop()

    listener = get_active_listener(ctx.workspace, lport)
    if listener is None or not listener.capture.connected:
        raise RuntimeError(
            f"no live shell on port {lport} — run postex from this dashboard session first"
        )

    if not listener.wait_probe(timeout=15.0):
        raise RuntimeError(
            f"shell on port {lport} still probing — wait a moment and retry attach"
        )

    ctx._shell_session = DashboardShellSession(ctx, listener, lport=lport)
    ctx._shell_session.start(emit_ready=emit_ready)
