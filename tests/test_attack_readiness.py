from __future__ import annotations

import json
from pathlib import Path

from admapper.analysis.attack_readiness import build_attack_readiness
from admapper.models.spray import DomainLockoutPolicy
from admapper.models.user import UserRecord


def _base_ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps(
            {
                "hosts": [
                    {
                        "address": "10.0.0.1",
                        "is_domain_controller": True,
                        "open_ports": [88, 389, 445],
                    }
                ]
            }
        )
    )
    (ws / "auth_inventory.json").write_text(
        json.dumps(
            {
                "users": [
                    UserRecord(
                        username="svc",
                        enabled=True,
                        dn="CN=svc,DC=lab,DC=local",
                    ).to_dict(),
                    UserRecord(
                        username="krbtgt",
                        enabled=True,
                        kerberoastable=True,
                        spns=["kadmin/changepw"],
                    ).to_dict(),
                ]
            }
        )
    )
    (ws / "credentials.json").write_text(
        json.dumps(
            {
                "credentials": [
                    {"username": "wallace", "status": "valid", "password": "x"},
                ]
            }
        )
    )
    (ws / "loot_manifest.json").write_text(
        json.dumps(
            {
                "parsed_credentials": [
                    {
                        "username": "svc",
                        "password": "Em3rg3ncy2025",
                        "source_file": "Logs/Trace_20260219.log",
                    }
                ]
            }
        )
    )
    return ws


def test_attack_readiness_includes_lockout_before_verify(tmp_path: Path) -> None:
    ws = _base_ws(tmp_path)
    policy = DomainLockoutPolicy(lockout_threshold=5, source_host="10.0.0.1")
    (ws / "lockout_policy.json").write_text(
        json.dumps(
            {
                "policy": policy.to_dict(),
                "user_states": [{"username": "svc", "bad_pwd_count": 1, "lockout_time": 0}],
            }
        )
    )
    users = [UserRecord.from_dict(u) for u in json.loads((ws / "auth_inventory.json").read_text())["users"]]
    users = [
        UserRecord(
            username=u.username,
            sources=list(u.sources),
            dn=u.dn,
            enabled=u.enabled,
            bad_pwd_count=1 if u.username == "svc" else u.bad_pwd_count,
        )
        if u.username == "svc"
        else u
        for u in users
    ]
    vectors = build_attack_readiness(ws, users=users, policy=policy, owned_users=["wallace"])

    verify = next(v for v in vectors if v["attack_id"].startswith("creds_verify:"))
    keys = [p["key"] for p in verify["prerequisites"]]
    assert keys.index("lockout_policy") < keys.index("attempts")
    assert verify["targets"][0]["attempts_remaining"] == 4

    spray = next(v for v in vectors if v["attack_id"] == "passwordspray")
    assert any(p["key"] == "lockout_policy" for p in spray["prerequisites"])


def test_kerberoast_requires_cred_and_clock(tmp_path: Path) -> None:
    ws = _base_ws(tmp_path)
    policy = DomainLockoutPolicy()
    users = [UserRecord.from_dict(u) for u in json.loads((ws / "auth_inventory.json").read_text())["users"]]
    vectors = build_attack_readiness(ws, users=users, policy=policy)
    krb = next(v for v in vectors if v["attack_id"] == "kerberoast")
    assert krb["ready"] is False
    assert any(p["key"] == "kerberos_clock" and not p["met"] for p in krb["prerequisites"])
