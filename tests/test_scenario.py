import json
from pathlib import Path

from admapper.report.scenario import (
    build_scenario_report,
    infer_kill_chain_phase,
    resolve_next_command,
    resolve_top_actions,
    roast_candidates_line,
)


def test_build_scenario_report_includes_loot_and_next(tmp_path: Path) -> None:
    ws = tmp_path / "target"
    ws.mkdir()
    (ws / "credentials.json").write_text(
        json.dumps(
            {
                "credentials": [
                    {
                        "id": "cred-001",
                        "username": "wallace.everette",
                        "status": "valid",
                        "type": "password",
                        "source": "run",
                        "secret": "x",
                    },
                    {
                        "id": "cred-002",
                        "username": "svc_recovery",
                        "status": "invalid",
                        "type": "password",
                        "source": "share_loot",
                        "secret": "y",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "loot_manifest.json").write_text(
        json.dumps(
            {
                "parsed_credentials": [
                    {
                        "username": "svc_recovery",
                        "password": "Em3rg3ncyPa$$2026",
                        "confidence": "high",
                        "pattern": "bind_user_pass",
                        "source_file": "Logs/script.ps1",
                    }
                ],
                "dc_ip": "10.129.20.182",
                "shares_looted": ["Logs", "SYSVOL"],
            }
        ),
        encoding="utf-8",
    )
    (ws / "unauth_scan.json").write_text(
        json.dumps(
            {
                "domain": "logging.htb",
                "hosts": [
                    {
                        "address": "10.129.20.182",
                        "is_domain_controller": True,
                        "open_ports": [88, 389, 445],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (ws / "auth_inventory.json").write_text(
        json.dumps(
            {
                "groups": [
                    {
                        "name": "Protected Users",
                        "members": ["CN=svc_recovery,CN=Users,DC=logging,DC=htb"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "acl_findings.json").write_text(json.dumps({"findings": []}), encoding="utf-8")

    text = build_scenario_report(
        ws,
        workspace="target",
        domain="logging.htb",
        owned_users=["wallace.everette"],
        pivot_user="wallace.everette",
    )

    assert "logging.htb" in text
    assert "wallace.everette" in text
    assert "svc_recovery" in text
    assert "Em3rg3ncyPa$$2026" in text
    assert "ACCIONES RECOMENDADAS" in text
    assert "[RECOMENDADO]" in text
    assert "MATRIZ DE ACCESO" in text
    assert "Logs" in text


def test_resolve_top_actions_gmsa_not_pywhisker(tmp_path: Path) -> None:
    ws = tmp_path / "gmsa_cmd"
    ws.mkdir()
    (ws / "credentials.json").write_text(json.dumps({"credentials": []}), encoding="utf-8")
    (ws / "acl_findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "acl-001",
                        "principal": "pivot",
                        "right": "GenericWrite",
                        "target_name": "msa_health",
                        "severity": "high",
                        "summary": "gMSA genericwrite",
                        "manual_commands": ["pywhisker --target msa_health -a add"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    actions = resolve_top_actions(
        ws,
        pivot="pivot",
        owned=["pivot"],
        domain="logging.htb",
        workspace="gmsa_cmd",
        limit=1,
    )
    assert "exploit" in actions[0].command
    assert "pywhisker" not in actions[0].command


def test_roast_candidates_from_auth_inventory(tmp_path: Path) -> None:
    ws = tmp_path / "roast"
    ws.mkdir()
    (ws / "auth_inventory.json").write_text(
        json.dumps(
            {
                "users": [
                    {
                        "username": "no_preauth",
                        "uac": 0x400000,
                        "asrep_roastable": True,
                        "enabled": True,
                    },
                    {
                        "username": "svc_sql",
                        "uac": 0x200,
                        "spns": ["MSSQLSvc/dc01.corp.local:1433"],
                        "kerberoastable": True,
                        "enabled": True,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    line = roast_candidates_line(ws)
    assert line is not None
    assert "asrep: no_preauth" in line
    assert "kerberoast: svc_sql" in line


def test_resolve_top_actions_returns_three(tmp_path: Path) -> None:
    ws = tmp_path / "actions"
    ws.mkdir()
    (ws / "acl_findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "acl-1",
                        "principal": "pivot",
                        "right": "GenericAll",
                        "target_name": "target",
                        "severity": "high",
                        "summary": "test",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "credentials.json").write_text(json.dumps({"credentials": []}), encoding="utf-8")

    actions = resolve_top_actions(
        ws,
        pivot="pivot",
        owned=["pivot"],
        domain="corp.local",
        workspace="actions",
        limit=3,
    )
    assert len(actions) >= 1
    assert actions[0].command


def test_infer_kill_chain_phase_loot(tmp_path: Path) -> None:
    ws = tmp_path / "phase"
    ws.mkdir()
    (ws / "loot_manifest.json").write_text(json.dumps({"file_count": 1}), encoding="utf-8")
    assert "Loot" in infer_kill_chain_phase(ws, [])


def test_next_action_skips_machine_pth_when_human_pivot(tmp_path: Path) -> None:
    ws = tmp_path / "logging"
    ws.mkdir()
    (ws / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {"account": "msa_health$", "nthash": "a" * 32},
                ],
            }
        ),
        encoding="utf-8",
    )
    (ws / "wsus_ops.json").write_text(
        json.dumps(
            {
                "opportunities": [
                    {
                        "id": "wsus-004",
                        "technique": "wsus_cert_chain",
                        "context": "jaylee.clifton",
                        "severity": "critical",
                        "title": "WSUS + AD CS certificate chain",
                        "prerequisites_met": True,
                        "manual_commands": ["admapper wsus -w logging-autonomous"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    owned = ["msa_health$", "jaylee.clifton"]
    next_cmd = resolve_next_command(
        ws,
        pivot="jaylee.clifton",
        owned=owned,
        domain="logging.htb",
        workspace="logging-autonomous",
    )
    assert "evil-winrm" not in next_cmd.lower()
    assert "msa_health" not in next_cmd.lower()
    assert "wsus" in next_cmd.lower()
