from __future__ import annotations

from admapper.core.config import GlobalConfig
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.models.host import HostRecord
from admapper.postex.creds import WinRMCred
from admapper.winrm.factory import winrm_client_for_cred


def test_winrm_client_prefers_workspace_dc_ip(tmp_path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("corp.local")
    HostsStore(manager, "lab").merge(
        [
            HostRecord(
                address="192.168.10.182",
                hostname="DC01.corp.local",
                is_domain_controller=True,
                open_ports=[88, 389, 445, 5985],
            )
        ]
    )

    cred = WinRMCred(
        username="msa_health$",
        domain="corp.local",
        host="msa_health.corp.local",
        nthash="7fdad697aa96c287e6d33381c3755b17",
    )
    client = winrm_client_for_cred(cred, session)
    assert client.dc_ip == "192.168.10.182"
    assert client.host == "192.168.10.182"
