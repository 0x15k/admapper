from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.core.platform import get_clock_skew
from admapper.creds.common import pick_dc_ip
from admapper.postex.creds import WinRMCred
from admapper.winrm.client import WinRMClient

if TYPE_CHECKING:
    from admapper.core.session import Session


def winrm_client_for_cred(
    cred: WinRMCred,
    session: Session | None = None,
) -> WinRMClient:
    """Build WinRMClient; PTH/SMB/nxc always prefer workspace DC IP over gMSA DNS names."""
    skew = get_clock_skew()
    dc_ip = pick_dc_ip(session) if session is not None else None
    if not dc_ip and cred.host and cred.host[0].isdigit():
        dc_ip = cred.host
    connect_host = dc_ip or cred.host
    dc_fqdn = cred.host if cred.host and cred.host != connect_host else None

    common = {
        "domain": cred.domain,
        "username": cred.username,
        "clock_skew": skew,
        "dc_ip": dc_ip,
        "dc_fqdn": dc_fqdn,
    }
    if cred.uses_nthash:
        return WinRMClient(
            connect_host,
            ticket_method="nthash",
            nthash=cred.nthash,
            **common,
        )
    return WinRMClient(
        connect_host,
        password=cred.password,
        ticket_method=WinRMClient.macos_recommended_method(),
        **common,
    )
