from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.models.finding import FindingSeverity
from admapper.recon.dns import DnsDiscovery, SrvRecord
from admapper.recon.ldap_probe import LdapProbeResult
from admapper.recon.smb_probe import SmbProbeResult
from admapper.recon.unauth import run_unauth_scan


def _session(tmp_path: Path) -> Session:
    manager = WorkspaceManager(tmp_path / "ws")
    return Session(config=GlobalConfig(), workspaces=manager)


def test_run_unauth_scan_persists_findings(tmp_path: Path) -> None:
    session = _session(tmp_path)
    session.select_workspace("lab")
    session.set_domain("corp.local")
    session.set_hosts("192.168.56.10")

    dns_result = DnsDiscovery(
        domain="corp.local",
        srv_records=[
            SrvRecord(
                service="_ldap._tcp",
                target="dc01.corp.local.",
                port=389,
                priority=0,
                weight=100,
            )
        ],
        domain_controllers=["dc01.corp.local"],
    )
    ldap_ok = LdapProbeResult(
        host="192.168.56.10",
        port=389,
        reachable=True,
        anonymous_bind=True,
        default_naming_context="DC=corp,DC=local",
        dns_host_name="dc01.corp.local",
    )
    smb_ok = SmbProbeResult(
        host="192.168.56.10",
        port=445,
        reachable=True,
        null_session=True,
    )

    with (
        patch("admapper.recon.unauth.discover_domain_dns", return_value=dns_result),
        patch("admapper.recon.unauth.scan_hosts", return_value={"192.168.56.10": [88, 389, 445]}),
        patch(
            "admapper.recon.unauth.discover_domain_from_ldap",
            return_value=("corp.local", "dc01.corp.local", ldap_ok),
        ),
        patch("admapper.recon.unauth.probe_ldap", return_value=ldap_ok),
        patch("admapper.recon.unauth.probe_smb_null", return_value=smb_ok),
        patch("admapper.recon.unauth.reverse_ptr", return_value="dc01.corp.local"),
    ):
        result = run_unauth_scan(session)

    assert result.domain == "corp.local"
    assert len(result.hosts) == 1
    assert result.hosts[0].is_domain_controller is True
    keys = {f.key for f in result.findings}
    assert "ldap_anonymous_192.168.56.10" in keys
    assert "smb_null_192.168.56.10" in keys

    findings_path = tmp_path / "ws" / "lab" / "findings.json"
    hosts_path = tmp_path / "ws" / "lab" / "hosts.json"
    report_path = tmp_path / "ws" / "lab" / "unauth_scan.json"
    assert findings_path.is_file()
    assert hosts_path.is_file()
    assert report_path.is_file()

    ldap_finding = next(f for f in result.findings if f.key.startswith("ldap_anonymous"))
    assert ldap_finding.severity == FindingSeverity.MEDIUM


def test_run_unauth_scan_falls_back_when_port_scan_empty(tmp_path: Path) -> None:
    session = _session(tmp_path)
    session.select_workspace("lab")
    session.set_hosts("192.168.10.182")

    ldap_ok = LdapProbeResult(
        host="192.168.10.182",
        port=389,
        reachable=True,
        anonymous_bind=False,
        default_naming_context="DC=corp,DC=local",
        dns_host_name="DC01.corp.local",
    )
    smb_ok = SmbProbeResult(host="192.168.10.182", port=445, reachable=True, null_session=False)

    with (
        patch("admapper.recon.unauth.scan_hosts", return_value={}),
        patch("admapper.recon.unauth.scan_host", return_value=[]),
        patch("admapper.recon.unauth.discover_domain_from_ldap", return_value=("corp.local", "dc01.corp.local", ldap_ok)),
        patch("admapper.recon.unauth.probe_ldap", return_value=ldap_ok),
        patch("admapper.recon.unauth.probe_smb_null", return_value=smb_ok),
        patch("admapper.recon.unauth.reverse_ptr", return_value="dc01.corp.local"),
    ):
        result = run_unauth_scan(session)

    assert result.domain == "corp.local"
    assert len(result.hosts) == 1
    assert session.workspace.domain == "corp.local"


def test_run_unauth_scan_domain_from_smb_null(tmp_path: Path) -> None:
    session = _session(tmp_path)
    session.select_workspace("lab")
    session.set_hosts("192.168.10.182")

    ldap_fail = LdapProbeResult(host="192.168.10.182", port=389, reachable=True, anonymous_bind=False)
    smb_ok = SmbProbeResult(
        host="192.168.10.182",
        port=445,
        reachable=True,
        null_session=True,
        dns_domain="corp.local",
        dns_hostname="dc01.corp.local",
    )

    with (
        patch("admapper.recon.unauth.scan_hosts", return_value={"192.168.10.182": [88, 389, 445, 636]}),
        patch("admapper.recon.unauth.discover_domain_from_ldap", return_value=(None, None, None)),
        patch("admapper.recon.unauth.probe_ldap", return_value=ldap_fail),
        patch("admapper.recon.unauth.probe_smb_null", return_value=smb_ok),
        patch("admapper.recon.unauth.reverse_ptr", return_value=None),
    ):
        result = run_unauth_scan(session)

    assert result.domain == "corp.local"
    assert result.hosts[0].hostname == "dc01.corp.local"
