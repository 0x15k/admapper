import json
from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.kerberos.timeroast import run_timeroast
from admapper.models.host import HostRecord


def test_run_timeroast_exports_targets(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("corp.local")
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[88, 389], is_domain_controller=True)]
    )

    inv = {
        "computers": [
            {
                "name": "WS01",
                "dn": "CN=WS01,DC=corp,DC=local",
                "dns_host": "ws01.corp.local",
            }
        ]
    }
    (tmp_path / "ws" / "lab" / "auth_inventory.json").write_text(
        json.dumps(inv),
        encoding="utf-8",
    )

    with (
        patch("admapper.kerberos.timeroast.confirm", return_value=True),
        patch("admapper.kerberos.timeroast.print_manual_guide"),
    ):
        result = run_timeroast(session)

    assert len(result.targets) == 1
    assert result.targets[0].computer == "WS01"
    assert (tmp_path / "ws" / "lab" / "timeroast_targets.json").is_file()
