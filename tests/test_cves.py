import json
from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.cves.detect import detect_cve_findings
from admapper.cves.discover import discover_cve_targets
from admapper.cves.enum_domain import DomainCveContext
from admapper.cves.os_parse import parse_operating_system
from admapper.cves.analyze import run_cve_analysis
from admapper.models.credential import CredentialStatus
from admapper.models.host import HostRecord


def test_parse_operating_system_server_2019() -> None:
    parsed = parse_operating_system("Windows Server 2019 Standard")
    assert parsed is not None
    assert parsed.family == "server"
    assert parsed.version == "2019"
    assert parsed.is_dc_candidate


def test_parse_operating_system_windows_7() -> None:
    parsed = parse_operating_system("Windows 7 Professional")
    assert parsed is not None
    assert parsed.is_legacy_smb


def test_detect_cve_findings_covers_phase16() -> None:
    from admapper.models.cve_finding import CveTarget

    targets = [
        CveTarget(
            host="dc01.target.example",
            computer_name="DC01",
            operating_system="Windows Server 2019 Standard",
            is_domain_controller=True,
            open_ports=[445],
        ),
        CveTarget(
            host="ws2008.target.example",
            computer_name="WS2008",
            operating_system="Windows Server 2008 R2 Standard",
            is_domain_controller=False,
            open_ports=[445],
        ),
    ]
    findings = detect_cve_findings(targets, machine_account_quota=10)
    techniques = {f.technique for f in findings}
    assert "nopac" in techniques
    assert "zerologon" in techniques
    assert "printnightmare" in techniques
    assert "eternalblue" in techniques
    assert "cve_catalog" in techniques


def test_discover_cve_targets_from_inventory_and_hosts(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")

    HostsStore(manager, "lab").merge(
        [
            HostRecord(
                address="10.0.0.1",
                hostname="dc01.target.example",
                open_ports=[445],
                is_domain_controller=True,
            )
        ]
    )
    inventory = {
        "computers": [
            {
                "name": "WS01",
                "dns_host": "ws01.target.example",
                "operating_system": "Windows 10 Pro",
            }
        ]
    }

    targets = discover_cve_targets(session, inventory)
    hosts = {t.host for t in targets}
    assert "ws01.target.example" in hosts
    assert "10.0.0.1" in hosts or "dc01.target.example" in hosts


def test_run_cve_analysis_writes_artifacts(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    session.workspace.owned_users = ["jsmith"]
    session.persist_workspace()

    HostsStore(manager, "lab").merge(
        [
            HostRecord(
                address="10.0.0.1",
                hostname="dc01.target.example",
                open_ports=[445],
                is_domain_controller=True,
            )
        ]
    )
    inventory = {
        "computers": [
            {
                "name": "DC01",
                "dns_host": "dc01.target.example",
                "operating_system": "Windows Server 2019 Standard",
            }
        ]
    }
    (tmp_path / "ws" / "lab" / "auth_inventory.json").write_text(
        json.dumps(inventory),
        encoding="utf-8",
    )
    cred = session.credentials.add("jsmith", "Secret123!", domain="target.example")
    session.credentials.mark_status(cred.id, CredentialStatus.VALID)

    domain_ctx = DomainCveContext(machine_account_quota=10, domain_controllers=["dc01.target.example"])

    with (
        patch("admapper.cves.analyze.enumerate_domain_cve_context", return_value=domain_ctx),
        patch("admapper.cves.analyze.print_manual_guide"),
    ):
        result = run_cve_analysis(session)

    assert result.findings
    assert (tmp_path / "ws" / "lab" / "cve_inventory.json").is_file()
    assert (tmp_path / "ws" / "lab" / "cve_findings.json").is_file()


def test_run_zerologon_exploit_requires_confirm(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")

    with (
        patch("admapper.cves.exploit.confirm", return_value=False),
        patch("admapper.cves.exploit.probe_zerologon") as mock_probe,
    ):
        from admapper.cves.exploit import run_zerologon_exploit

        ok = run_zerologon_exploit(session, "dc01.target.example")

    assert ok is False
    mock_probe.assert_not_called()
