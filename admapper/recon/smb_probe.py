from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SmbProbeResult:
    host: str
    port: int
    reachable: bool = False
    null_session: bool = False
    guest_access: bool = False
    signing_required: bool | None = None
    dns_domain: str | None = None
    dns_hostname: str | None = None
    error: str | None = None


def probe_smb_null(host: str, *, port: int = 445, timeout: int = 5) -> SmbProbeResult:
    """Attempt SMB null-session login via Impacket when available."""
    result = SmbProbeResult(host=host, port=port)
    try:
        from impacket.smbconnection import SessionError, SMBConnection
    except ImportError:
        result.error = "impacket not installed — SMB null-session probe skipped"
        return result

    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
        result.reachable = True
        try:
            conn.login("", "")
            result.null_session = True
            domain = (conn.getServerDNSDomainName() or "").strip().lower()
            hostname = (conn.getServerDNSHostName() or "").strip().lower()
            if domain:
                result.dns_domain = domain
            if hostname:
                result.dns_hostname = hostname
        except SessionError as exc:
            result.error = str(exc)
        try:
            conn.logoff()
        except Exception:
            pass
    except Exception as exc:
        result.error = str(exc)
    return result
