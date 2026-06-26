import json
from pathlib import Path
from unittest.mock import patch

from admapper.coerce.analyze import build_coerce_opportunities, run_coerce_analysis
from admapper.core.config import GlobalConfig
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.models.host import HostRecord


def test_build_coerce_opportunities_with_dc_and_esc8(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[88], is_domain_controller=True)]
    )

    inventory = {
        "delegations": [
            {
                "object_name": "DELEG01",
                "delegation_type": "unconstrained",
                "object_type": "computer",
            }
        ],
        "computers": [
            {"name": "DELEG01", "unconstrained_delegation": True},
        ],
        "smb_signing_required": False,
    }
    adcs_data = {
        "findings": [{"esc": "esc8", "ca_name": "corp-CA"}],
        "enrollment_services": [
            {"name": "corp-CA", "dns_host": "ca01.target.example", "web_enrollment": True}
        ],
    }

    ops = build_coerce_opportunities(
        session,
        inventory=inventory,
        adcs_data=adcs_data,
        kerberos_data=None,
        acl_data=None,
    )
    techniques = {o.technique for o in ops}
    assert "petitpotam" in techniques
    assert "printerbug" in techniques
    assert "dfscoerce" in techniques
    assert "relay_ldap" in techniques
    assert "relay_adcs" in techniques
    assert "relay_ntlmv1" in techniques
    assert any(o.listener_host == "DELEG01" for o in ops)


def test_run_coerce_analysis_writes_playbook(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[88], is_domain_controller=True)]
    )

    inv = {
        "delegations": [],
        "computers": [],
        "smb_signing_required": True,
    }
    (tmp_path / "ws" / "lab" / "auth_inventory.json").write_text(
        json.dumps(inv),
        encoding="utf-8",
    )

    with patch("admapper.coerce.analyze.print_manual_guide"):
        result = run_coerce_analysis(session)

    assert result.opportunities
    assert (tmp_path / "ws" / "lab" / "coerce_ops.json").is_file()
