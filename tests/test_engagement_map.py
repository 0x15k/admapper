import json
from pathlib import Path

from admapper.report.engagement_map import build_engagement_map


def test_engagement_map_shows_next_hop_and_krb5_blocker(tmp_path: Path) -> None:
    ws = tmp_path / "target"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps(
            {
                "domain": "corp.local",
                "hosts": [
                    {
                        "address": "192.168.10.182",
                        "hostname": "dc01.corp.local",
                        "is_domain_controller": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (ws / "credentials.json").write_text(
        json.dumps(
            {
                "credentials": [
                    {
                        "id": "c1",
                        "username": "svc_sql",
                        "secret": "WelcomePassword123!",
                        "status": "valid",
                        "type": "password",
                        "source": "manual",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "password_candidates.json").write_text(
        json.dumps(
            {
                "candidates": [
                    {
                        "username": "svc_sql",
                        "password": "WelcomePassword123!",
                        "verified": True,
                        "reason": "stale_log_year_variant",
                    }
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
                        "username": "svc_sql",
                        "password": "WelcomePassword123!",
                        "source_file": "Logs/trace.log",
                        "confidence": "medium",
                    }
                ]
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
                        "members": ["CN=svc_sql,CN=Users,DC=logging,DC=htb"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "acl_findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "acl-001",
                        "principal": "svc_sql",
                        "right": "genericwrite",
                        "target_name": "msa_health",
                        "severity": "high",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "exploit_log.json").write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "phase": "acl_exploit",
                        "status": "skipped",
                        "detail": "kinit failed: MIT krb5 not found",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    text = build_engagement_map(
        ws,
        workspace="target",
        domain="corp.local",
        owned_users=["svc_sql"],
        pivot_user="svc_sql",
    )

    assert "MAPA DE ENGAGEMENT" in text
    assert "svc_sql" in text
    assert "WelcomePassword123!" in text
    assert "SIGUIENTE PASO" in text
    assert "genericwrite" in text
    assert "msa_health" in text
    assert "BLOQUEO" in text
    assert "krb5-user" in text or "krb5" in text


def test_engagement_map_shows_hash_and_winrm_next_hop(tmp_path: Path) -> None:
    ws = tmp_path / "target"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps(
            {
                "domain": "corp.local",
                "hosts": [
                    {
                        "address": "192.168.10.182",
                        "hostname": "dc01.corp.local",
                        "is_domain_controller": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (ws / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {
                        "account": "msa_health$",
                        "nthash": "0123456789abcdef0123456789abcdef",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    text = build_engagement_map(
        ws,
        workspace="target",
        domain="corp.local",
        owned_users=["svc_sql", "msa_health$"],
        pivot_user="msa_health$",
    )

    assert "HASH OBTENIDO" in text
    assert "0123456789abcdef0123456789abcdef" in text
    assert "dc01.corp.local" in text
    assert "WinRM" in text
    assert "SIGUIENTE PASO" in text
    assert "──WinRM──►" in text



def test_engagement_map_advances_past_confirmed_winrm(tmp_path: Path) -> None:
    ws = tmp_path / "target"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps(
            {
                "domain": "corp.local",
                "hosts": [
                    {
                        "address": "192.168.10.182",
                        "hostname": "dc01.corp.local",
                        "is_domain_controller": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (ws / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {
                        "account": "msa_health$",
                        "nthash": "7fdad697aa96c287e6d33381c3755b17",
                    }
                ],
                "steps": [
                    {
                        "phase": "lateral_winrm",
                        "status": "success",
                        "detail": "msa_health$ @ msa_health.corp.local",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (ws / "postex_scan.json").write_text(
        json.dumps(
            {
                "shell_user": "msa_health$",
                "findings": [
                    {
                        "task_name": "Update Check",
                        "run_as_user": "jaylee.doe",
                        "payload_zip": "Settings_Update.zip",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (ws / "postex_ops.json").write_text(
        json.dumps(
            {
                "opportunities": [
                    {
                        "id": "postex-001",
                        "technique": "dll_hijack_scheduled_task",
                        "title": "Scheduled task DLL hijack",
                        "severity": "critical",
                        "detail": "Task 'Update Check' runs as jaylee.doe | Drop Settings_Update.zip",
                        "context": "msa_health$",
                        "manual_commands": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    text = build_engagement_map(
        ws,
        workspace="target",
        domain="corp.local",
        owned_users=["wallace.doe", "msa_health$"],
        pivot_user="msa_health$",
    )

    assert "──WinRM──►" not in text
    assert "SIGUIENTE PASO" in text
    assert "dll_hijack_scheduled_task" in text
    assert "jaylee.doe" in text
