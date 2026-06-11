from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

from admapper.core.platform import run_command, tool_install_hint
from admapper.models.ad_object import GppCredential
from admapper.models.credential import Credential, CredentialType

_GPP_LINE_RE = re.compile(
    r"(?:\[+\]|GPP)\s*(?:password\s+)?(?P<user>\S+?)(?::\s*|\s+)(?P<pass>\S+)",
    re.IGNORECASE,
)


@dataclass
class SmbAuthEnumResult:
    shares: list[str] = field(default_factory=list)
    gpp_credentials: list[GppCredential] = field(default_factory=list)
    signing_required: bool | None = None
    error: str | None = None


def enumerate_smb_authenticated(
    host: str,
    cred: Credential,
    domain: str,
    *,
    timeout: int = 15,
) -> SmbAuthEnumResult:
    """Phase 8.4–8.5 — SMB shares, signing, GPP (requires impacket)."""
    result = SmbAuthEnumResult()
    if cred.cred_type != CredentialType.PASSWORD:
        result.error = "SMB auth enum requires password credential"
        return result

    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        result.error = f"impacket not installed — {tool_install_hint('impacket')}"
        return result

    try:
        smb = SMBConnection(host, host, sess_port=445, timeout=timeout)
        smb.login(cred.username, cred.secret, domain)
        try:
            result.signing_required = bool(getattr(smb, "isSigningRequired", lambda: False)())
        except Exception:
            result.signing_required = None
        for share in smb.listShares():
            name = share["shi1_netname"][:-1]
            if name not in ("IPC$", "PRINT$"):
                result.shares.append(name)
        result.shares = sorted(result.shares)
    except Exception as exc:
        result.error = str(exc)

    gpp, gpp_err = _enumerate_gpp(host, cred, domain, timeout=timeout)
    result.gpp_credentials = gpp
    if gpp_err and not gpp:
        result.error = (result.error or "") + f"; gpp: {gpp_err}" if result.error else gpp_err
    return result


def _enumerate_gpp(
    host: str,
    cred: Credential,
    domain: str,
    *,
    timeout: int = 120,
) -> tuple[list[GppCredential], str | None]:
    """GPP via nxc (impacket 0.12+ removed GetGPPPassword example script)."""
    from admapper.core.platform import resolve_nxc

    nxc = resolve_nxc()
    if not nxc:
        return [], None

    cmd = [
        nxc,
        "smb",
        host,
        "-u",
        cred.username,
        "-p",
        cred.secret,
        "-d",
        domain,
        "-M",
        "gpp_password",
    ]
    try:
        proc = run_command(cmd, timeout=timeout)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        creds: list[GppCredential] = []
        for line in output.splitlines():
            match = _GPP_LINE_RE.search(line)
            if match:
                creds.append(
                    GppCredential(
                        user=match.group("user"),
                        password=match.group("pass"),
                        source_file="SYSVOL",
                    )
                )
            elif "cpassword" in line.lower() and ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    creds.append(
                        GppCredential(
                            user=parts[0].strip().split()[-1],
                            password=parts[1].strip(),
                            source_file="SYSVOL",
                        )
                    )
        if creds:
            return creds, None
        if proc.returncode != 0 and "No module" in output:
            return [], None
        return creds, None if proc.returncode == 0 else None
    except subprocess.TimeoutExpired:
        return [], "GPP enum timed out"
    except OSError as exc:
        return [], str(exc)
