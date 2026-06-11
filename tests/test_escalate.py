from pathlib import Path

from admapper.escalate.edges import collect_edges_from_pivot, pick_next_edge


def test_escalate_picks_dll_hijack_from_msa_health(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "postex_ops.json").write_text(
        """
        {"opportunities": [{
            "id": "postex-010",
            "technique": "dll_hijack_scheduled_task",
            "context": "msa_health$",
            "severity": "critical",
            "title": "DLL hijack",
            "detail": "Task 'UpdateChecker Agent' runs as jaylee.clifton | Binary: x",
            "manual_commands": ["postex run --op postex-010"]
        }]}
        """,
        encoding="utf-8",
    )
    (ws / "postex_scan.json").write_text(
        '{"findings": [{"run_as_user": "jaylee.clifton"}]}',
        encoding="utf-8",
    )
    edges = collect_edges_from_pivot(
        pivot_user="msa_health$",
        owned_users=["msa_health$"],
        ws_path=ws,
        domain="logging.htb",
    )
    nxt = pick_next_edge(edges)
    assert nxt is not None
    assert nxt.technique == "dll_hijack_scheduled_task"
    assert nxt.target == "jaylee.clifton"


def test_escalate_jaylee_prefers_wsus_over_server_auth_template(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "auth_inventory.json").write_text(
        """
        {"users": [{"username": "jaylee.clifton", "dn": "CN=jaylee,DC=logging,DC=htb"}],
         "groups": [{"name": "IT", "members": ["CN=jaylee,DC=logging,DC=htb"]}]}
        """,
        encoding="utf-8",
    )
    (ws / "adcs_findings.json").write_text(
        """
        {"findings": [{
            "id": "adcs-002",
            "esc": "template_enrollment",
            "principal": "jaylee.clifton",
            "template": "UpdateSrv",
            "wsus_chain_step": true,
            "cert_auth_viable": false,
            "severity": "high",
            "title": "UpdateSrv enrollment → WSUS chain",
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
            "context": "jaylee.clifton",
            "severity": "critical",
            "title": "WSUS + AD CS certificate chain",
            "prerequisites_met": true,
            "manual_commands": ["pywsus ..."]
        }]}
        """,
        encoding="utf-8",
    )
    edges = collect_edges_from_pivot(
        pivot_user="jaylee.clifton",
        owned_users=["msa_health$", "jaylee.clifton"],
        ws_path=ws,
        domain="logging.htb",
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
            "principal": "svc_recovery",
            "right": "genericwrite",
            "target_name": "msa_health",
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
            "context": "msa_health$",
            "severity": "high",
            "detail": "runs as jaylee.clifton"
        }]}
        """,
        encoding="utf-8",
    )
    (ws / "postex_scan.json").write_text(
        '{"findings": [{"run_as_user": "jaylee.clifton"}]}',
        encoding="utf-8",
    )
    edges = collect_edges_from_pivot(
        pivot_user="msa_health$",
        owned_users=["svc_recovery", "msa_health$"],
        ws_path=ws,
        domain="logging.htb",
    )
    nxt = pick_next_edge(edges)
    assert nxt is not None
    assert nxt.technique == "dll_hijack_scheduled_task"
