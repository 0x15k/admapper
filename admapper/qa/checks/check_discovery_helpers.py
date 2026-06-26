import json
from pathlib import Path

from admapper.core.config import GlobalConfig
from admapper.core.discovery import default_workspace_name, ensure_domain, resolve_domain
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.recon.dns import dn_to_domain


def test_dn_to_domain() -> None:
    assert dn_to_domain("DC=target,DC=example") == "target.example"


def test_default_workspace_name_from_ip() -> None:
    assert default_workspace_name("192.168.10.130") == "target-192-168-10-130"


def test_resolve_domain_from_findings(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")

    ws_path = tmp_path / "ws" / "lab"
    ws_path.mkdir(parents=True, exist_ok=True)
    (ws_path / "findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "key": "ldap_anonymous_10.0.0.1",
                        "detail": "DC=target,DC=example",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert resolve_domain(session) == "target.example"


def test_ensure_domain_persists_on_session(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")

    ws_path = tmp_path / "ws" / "lab"
    ws_path.mkdir(parents=True, exist_ok=True)
    (ws_path / "unauth_scan.json").write_text(
        json.dumps({"domain": "target.example"}),
        encoding="utf-8",
    )

    domain = ensure_domain(session, announce=False)
    assert domain == "target.example"
    assert session.workspace.domain == "target.example"
