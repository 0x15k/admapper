from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from admapper.core.output import print_info
from admapper.core.platform import is_macos, resolve_executable, resolve_nxc, run_command, tool_install_hint
from admapper.postex.evil_winrm_output import strip_evil_winrm_output
from admapper.postex.hijack_intel import parse_schtasks_list_output
from admapper.postex.nxc_output import strip_nxc_winrm_output
from admapper.winrm.deps import WinRMDeps, check_winrm_deps, winrm_deps_hint
from admapper.winrm.tickets import (
    TicketError,
    default_ticket_dir,
    impacket_tickets,
    klist_text,
    mit_kinit,
    winrm_host_candidates,
    write_krb5_conf,
)


class WinRMError(RuntimeError):
    pass


def _cmd_to_powershell(command: str) -> str:
    """Map common CMD aliases when the remote shell lacks Invoke rights."""
    mapping = {
        "dir": "Get-ChildItem",
        "ls": "Get-ChildItem",
        "pwd": "Get-Location",
        "whoami": "whoami",
    }
    key = command.strip().lower().split()[0]
    if key in mapping and command.strip().lower() == key:
        return mapping[key]
    if key in mapping:
        rest = command.strip()[len(key) :].strip()
        return f"{mapping[key]} {rest}".strip()
    return command


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    returncode: int
    shell: str


class WinRMClient:
    """PyPSRP WinRM client with Kerberos — macOS alternative to evil-winrm."""

    def __init__(
        self,
        host: str,
        *,
        domain: str,
        username: str,
        password: str | None = None,
        dc_ip: str | None = None,
        dc_fqdn: str | None = None,
        port: int = 5985,
        ticket_method: Literal["mit", "impacket", "ccache", "nthash"] = "mit",
        ccache: Path | None = None,
        krb5_conf: Path | None = None,
        clock_skew: str | None = None,
        verbose: bool = False,
        nthash: str | None = None,
    ) -> None:
        self.host = host.rstrip(".")
        self.domain = domain
        self.username = username.split("@")[0]
        self.password = password
        self.dc_ip = dc_ip
        self.dc_fqdn = dc_fqdn or self.host
        self.port = port
        self.ticket_method = ticket_method
        self.ccache = ccache
        self.krb5_conf = krb5_conf or default_ticket_dir() / f"{domain.lower()}-krb5.conf"
        self.clock_skew = clock_skew
        self.verbose = verbose
        self.nthash = nthash.lower() if nthash else None
        self._client = None
        self._env: dict[str, str] = {}
        self._connected_host: str | None = None
        self._nthash_target: str | None = None
        self.last_raw_output: str = ""

    def _require_deps(self) -> WinRMDeps:
        if self.ticket_method == "nthash":
            if not resolve_nxc():
                raise WinRMError(f"nxc required for Pass-the-Hash WinRM.\n{tool_install_hint('nxc')}")
            return check_winrm_deps()
        deps = check_winrm_deps()
        if not deps.pypsrp or not deps.gssapi or not deps.krb5:
            raise WinRMError(f"WinRM dependencies missing.\n{winrm_deps_hint(deps)}")
        return deps

    def _candidate_hosts(self) -> list[str]:
        return winrm_host_candidates(self.domain, self.dc_fqdn)

    def _prepare_tickets(self) -> None:
        if not self.dc_ip:
            raise WinRMError("dc_ip is required to acquire Kerberos tickets")

        ticket_dir = default_ticket_dir()
        ccache = self.ccache or ticket_dir / f"{self.username}-winrm.ccache"
        self.ccache = ccache

        if self.ticket_method == "ccache":
            if not ccache.is_file():
                raise TicketError(f"ccache not found: {ccache}")
        elif self.ticket_method == "impacket":
            if not self.password:
                raise TicketError("password required for impacket ticket method")
            self.ccache = impacket_tickets(
                username=self.username,
                password=self.password,
                domain=self.domain,
                dc_fqdn=self.dc_fqdn,
                dc_ip=self.dc_ip,
                workdir=ticket_dir,
                clock_skew=self.clock_skew,
            )
        else:
            if not self.password:
                raise TicketError("password required for mit kinit")
            if self.verbose:
                print_info(f"Kerberos SPN hosts: {', '.join(winrm_host_candidates(self.domain, self.dc_fqdn))}")
            obtained = mit_kinit(
                username=self.username,
                password=self.password,
                domain=self.domain,
                dc_fqdn=self.dc_fqdn,
                dc_ip=self.dc_ip,
                ccache=ccache,
                krb5_conf=self.krb5_conf,
                verbose=self.verbose,
            )
            if self.verbose and obtained:
                print_info(f"tickets: {', '.join(obtained)}")
                listing = klist_text(ccache, self.krb5_conf)
                if listing:
                    print_info(listing)

        write_krb5_conf(self.krb5_conf, domain=self.domain, dc_ip=self.dc_ip)
        self._env = {
            "KRB5_CONFIG": str(self.krb5_conf.resolve()),
            "KRB5CCNAME": f"FILE:{self.ccache.resolve()}",
        }

    def _nthash_target_host(self) -> str:
        if self.dc_ip and self.dc_ip[0].isdigit():
            return self.dc_ip
        return self.host

    def _run_nxc_winrm(
        self,
        command: str,
        *,
        shell: Literal["cmd", "powershell"] = "cmd",
    ) -> CommandResult:
        nxc = resolve_nxc()
        if not nxc or not self.nthash:
            raise WinRMError("nthash WinRM requires nxc and --hash")

        user = self.username if self.username.endswith("$") else f"{self.username}$"
        target = self._nthash_target or self._nthash_target_host()
        cmd = [nxc, "winrm", target, "-u", user, "-H", self.nthash, "-d", self.domain, "--no-progress"]
        if shell == "powershell":
            cmd.extend(["-X", command])
        else:
            cmd.extend(["-x", command])
        if self.verbose:
            print_info(f"nxc: {' '.join(cmd)}")
        proc = run_command(cmd, timeout=180, use_clock_skew=False)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        self.last_raw_output = output.strip()
        stdout = strip_nxc_winrm_output(output)
        rc = proc.returncode
        if rc != 0 and "FAIL" in output.upper() and not stdout:
            raise WinRMError(stdout or output.strip() or f"nxc winrm failed ({rc})")
        return CommandResult(stdout=stdout, stderr="", returncode=rc, shell=shell)

    def _run_evil_winrm(
        self,
        command: str,
        *,
        shell: Literal["cmd", "powershell"] = "cmd",
        timeout: int = 90,
    ) -> CommandResult:
        """Fallback when nxc -x/-X returns empty but PTH auth works."""
        ew = resolve_executable(["evil-winrm"])
        if not ew or not self.nthash:
            raise WinRMError("evil-winrm not found for PTH fallback")

        user_arg = f"{self.domain}\\{self.username}"
        # evil-winrm -c already runs inside PowerShell; cmd needs cmd.exe /c
        if shell == "powershell":
            remote_cmd = command
        else:
            remote_cmd = f"cmd.exe /c {command}"

        target = self._nthash_target or self._nthash_target_host()
        cmd = [ew, "-i", target, "-u", user_arg, "-H", self.nthash, "-c", remote_cmd]
        if self.verbose:
            print_info(f"evil-winrm fallback: {' '.join(cmd[:6])} -c <cmd>")
        try:
            proc = run_command(cmd, timeout=timeout, use_clock_skew=False)
        except subprocess.TimeoutExpired as exc:
            partial = ""
            if exc.stdout:
                partial = exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode(errors="replace")
            self.last_raw_output = partial or f"evil-winrm timeout after {timeout}s"
            raise WinRMError(f"evil-winrm timeout: {command[:80]}…") from exc
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        self.last_raw_output = output.strip()
        rc = proc.returncode
        if rc != 0 and not output.strip():
            raise WinRMError(f"evil-winrm failed ({rc})")
        cleaned = strip_evil_winrm_output(output)
        if "TaskName:" in cleaned and "|" not in cleaned.splitlines()[0]:
            cleaned = parse_schtasks_list_output(cleaned) or cleaned
        return CommandResult(stdout=cleaned.strip(), stderr="", returncode=rc, shell=shell)

    def connect(self) -> None:
        self._require_deps()
        if self.ticket_method == "nthash":
            result = self._run_nxc_winrm("whoami")
            self._nthash_target = self._nthash_target_host()
            self._connected_host = self._nthash_target
            if self.verbose:
                print_info(f"WinRM PTH OK: {self.username} @ {self._nthash_target}")
            if not result.stdout and result.returncode != 0:
                raise WinRMError("WinRM Pass-the-Hash auth failed")
            return

        if self._client is None:
            self._prepare_tickets()

        for key, val in self._env.items():
            os.environ[key] = val

        from pypsrp.client import Client

        realm = self.domain.upper()
        principal = f"{self.username}@{realm}"
        last_err: Exception | None = None
        auth_modes: list[tuple[str, str | None]] = [
            ("kerberos", "HTTP"),
            ("negotiate", "HTTP"),
            ("kerberos", "WSMAN"),
            ("negotiate", None),
        ]

        for target_host in self._candidate_hosts():
            for auth, service in auth_modes:
                try:
                    kwargs: dict = {
                        "port": self.port,
                        "auth": auth,
                        "username": principal,
                        "password": None,
                        "ssl": False,
                        "cert_validation": False,
                        "negotiate_hostname_override": target_host,
                    }
                    if service:
                        kwargs["negotiate_service"] = service
                    client = Client(target_host, **kwargs)
                    # Auth happens on first request
                    client.execute_cmd("whoami")
                    self._client = client
                    self._connected_host = target_host
                    if self.verbose:
                        print_info(f"WinRM auth OK: {target_host} auth={auth} service={service or 'default'}")
                    return
                except Exception as exc:
                    last_err = exc
                    if self.verbose:
                        print_info(f"try {target_host} {auth}/{service}: {exc}")

        raise WinRMError(
            f"WinRM Kerberos failed for {principal} — tried hosts "
            f"{self._candidate_hosts()}: {last_err}"
        )

    def execute(
        self,
        command: str,
        *,
        shell: Literal["cmd", "powershell"] = "cmd",
        timeout: int | None = None,
    ) -> CommandResult:
        if self.ticket_method == "nthash":
            if self._connected_host is None:
                self.connect()
            result = self._run_nxc_winrm(command, shell=shell)
            if (result.stdout or "").strip():
                return result
            try:
                fb = self._run_evil_winrm(command, shell=shell, timeout=timeout or 90)
                if (fb.stdout or "").strip():
                    print_info("WinRM: nxc returned no output — executed via evil-winrm")
                    return fb
                if fb.returncode == 0 or getattr(self, "last_raw_output", ""):
                    return fb
            except WinRMError:
                pass
            return result
        if self._client is None:
            self.connect()
        assert self._client is not None
        try:
            if shell == "powershell":
                stdout, stderr, rc = self._client.execute_ps(command)
                out = stdout or ""
                err = "\n".join(str(m) for m in (stderr.error or []) if str(m) != "None")
            else:
                raw_out, raw_err, rc = self._client.execute_cmd(command)
                out = raw_out.decode() if isinstance(raw_out, bytes) else (raw_out or "")
                err = raw_err.decode() if isinstance(raw_err, bytes) else (raw_err or "")
            return CommandResult(stdout=out, stderr=err, returncode=rc, shell=shell)
        except Exception as exc:
            raise WinRMError(f"command failed: {exc}") from exc

    def interactive_shell(self) -> None:
        if self._client is None and self._connected_host is None:
            self.connect()
        label = self._connected_host or self.host
        mode = "PTH/nxc" if self.ticket_method == "nthash" else "pypsrp"
        print(f"WinRM shell ({mode}) on {label} as {self.username} (exit/quit; ps: for PowerShell)")
        while True:
            try:
                line = input("CMD> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if line.lower() in ("exit", "quit"):
                break
            if not line:
                continue
            shell: Literal["cmd", "powershell"] = "powershell" if line.startswith("ps:") else "cmd"
            cmd = line[3:].strip() if shell == "powershell" else line
            try:
                result = self.execute(cmd, shell=shell)
                if result.stdout:
                    print(result.stdout.rstrip())
                if result.stderr:
                    print(result.stderr.rstrip())
                if result.returncode not in (0, None):
                    print(f"[exit {result.returncode}]")
            except WinRMError as exc:
                print(f"error: {exc}")

    @staticmethod
    def macos_recommended_method() -> str:
        return "mit" if is_macos() else "impacket"
