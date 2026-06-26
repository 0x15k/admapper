from pathlib import Path

from admapper.escalate.edges import collect_edges_from_pivot, pick_next_edge


def test_escalate_picks_dll_hijack_from_msa_target(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "postex_ops.json").write_text(
        """
        {"opportunities": [{
            "id": "postex-010",
            "technique": "dll_hijack_scheduled_task",
            "context": "msa_target$",
            "severity": "critical",
            "title": "DLL hijack",
            "detail": "Task 'UpdateChecker Agent' runs as target.admin | Binary: x",
            "manual_commands": ["postex run --op postex-010"]
        }]}
        """,
        encoding="utf-8",
    )
    (ws / "postex_scan.json").write_text(
        '{"findings": [{"run_as_user": "target.admin"}]}',
        encoding="utf-8",
    )
    edges = collect_edges_from_pivot(
        pivot_user="msa_target$",
        owned_users=["msa_target$"],
        ws_path=ws,
        domain="target.example",
    )
    nxt = pick_next_edge(edges)
    assert nxt is not None
    assert nxt.technique == "dll_hijack_scheduled_task"
    assert nxt.target == "target.admin"


def test_escalate_jaylee_prefers_wsus_over_server_auth_template(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "auth_inventory.json").write_text(
        """
        {"users": [{"username": "target.admin", "dn": "CN=target.admin,DC=target,DC=example"}],
         "groups": [{"name": "IT", "members": ["CN=target.admin,DC=target,DC=example"]}]}
        """,
        encoding="utf-8",
    )
    (ws / "adcs_findings.json").write_text(
        """
        {"findings": [{
            "id": "adcs-002",
            "esc": "template_enrollment",
            "principal": "target.admin",
            "template": "TargetSrv",
            "wsus_chain_step": true,
            "cert_auth_viable": false,
            "severity": "high",
            "title": "TargetTemplate enrollment → WSUS chain",
            "prerequisites_met": true,
            "manual_commands": ["certipy req ..."]
        }]}
        """,
        encoding="utf-8",
    )
    (ws / "wsus_ops.json").write_text(
        """
        {"opportunities": [{
            "id": "wsus-004",
            "technique": "wsus_cert_chain",
            "context": "target.admin",
            "severity": "critical",
            "title": "WSUS + AD CS certificate chain",
            "prerequisites_met": true,
            "manual_commands": ["pywsus ..."]
        }]}
        """,
        encoding="utf-8",
    )
    edges = collect_edges_from_pivot(
        pivot_user="target.admin",
        owned_users=["msa_target$", "target.admin"],
        ws_path=ws,
        domain="target.example",
    )
    nxt = pick_next_edge(edges)
    assert nxt is not None
    assert nxt.module == "wsus"
    assert nxt.technique == "wsus_cert_chain"


def test_escalate_skips_exploited_gmsa_acl_when_machine_owned(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "acl_findings.json").write_text(
        """
        {"findings": [{
            "id": "acl-001",
            "principal": "svc_user",
            "right": "genericwrite",
            "target_name": "msa_target",
            "severity": "high"
        }]}
        """,
        encoding="utf-8",
    )
    (ws / "postex_ops.json").write_text(
        """
        {"opportunities": [{
            "id": "postex-001",
            "technique": "dll_hijack_scheduled_task",
            "context": "msa_target$",
            "severity": "high",
            "detail": "runs as target.admin"
        }]}
        """,
        encoding="utf-8",
    )
    (ws / "postex_scan.json").write_text(
        '{"findings": [{"run_as_user": "target.admin"}]}',
        encoding="utf-8",
    )
    edges = collect_edges_from_pivot(
        pivot_user="msa_target$",
        owned_users=["svc_user", "msa_target$"],
        ws_path=ws,
        domain="target.example",
    )
    nxt = pick_next_edge(edges)
    assert nxt is not None
    assert nxt.technique == "dll_hijack_scheduled_task"


def test_escalate_gpo_abuse_edge(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "auth_inventory.json").write_text(
        """
        {
          "users": [
            {"username": "attacker", "dn": "CN=attacker,CN=Users,DC=target,DC=example"}
          ],
          "computers": [
            {"name": "srv01", "dn": "CN=srv01,OU=Servers,DC=target,DC=example"}
          ],
          "ous": [
            {"name": "Servers", "dn": "OU=Servers,DC=target,DC=example", "gplink": "[LDAP://CN={abc-123},CN=Policies,CN=System,DC=target,DC=example;0]"}
          ],
          "gpos": [
            {"name": "{abc-123}", "dn": "CN={abc-123},CN=Policies,CN=System,DC=target,DC=example", "display_name": "VulnerableGPO"}
          ]
        }
        """,
        encoding="utf-8",
    )
    (ws / "acl_findings.json").write_text(
        """
        {
          "findings": [{
            "id": "acl-001",
            "principal": "attacker",
            "right": "genericwrite",
            "target_dn": "CN={abc-123},CN=Policies,CN=System,DC=target,DC=example",
            "target_name": "VulnerableGPO",
            "target_type": "gpo",
            "severity": "high",
            "summary": "Write access to GPO VulnerableGPO"
          }]
        }
        """,
        encoding="utf-8",
    )
    edges = collect_edges_from_pivot(
        pivot_user="attacker",
        owned_users=["attacker"],
        ws_path=ws,
        domain="target.example",
    )
    gpo_edges = [e for e in edges if e.technique == "gpo_abuse"]
    assert len(gpo_edges) == 1
    assert gpo_edges[0].target == "srv01"


def test_escalate_stale_admin_count_shadow_admin(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    from unittest.mock import MagicMock, patch
    session = MagicMock()
    session.workspace.name = "lab"
    session.workspace.domain = "target.example"
    session.workspace.owned_users = ["attacker"]
    session.workspaces.path_for.return_value = ws
    (ws / "auth_inventory.json").write_text(
        """
        {
          "users": [
            {"username": "shadow_user", "dn": "CN=shadow,CN=Users,DC=target,DC=example", "admin_count": 1},
            {"username": "attacker", "dn": "CN=attacker,CN=Users,DC=target,DC=example"}
          ],
          "groups": [
            {"name": "Domain Admins", "dn": "CN=Domain Admins,CN=Users,DC=target,DC=example", "members": []}
          ]
        }
        """,
        encoding="utf-8",
    )
    from admapper.escalate.analyze import run_escalate_analysis
    findings = []
    class MockFindingsStore:
        def __init__(self, workspaces, ws_name):
            pass
        def merge(self, new_findings):
            findings.extend(new_findings)
            return new_findings
    with patch("admapper.core.findings.FindingsStore", MockFindingsStore):
        run_escalate_analysis(session, pivot_user="attacker", quiet=True)
    assert len(findings) == 1
    assert findings[0].key == "stale_admin_count"
    assert "shadow_user" in findings[0].detail
