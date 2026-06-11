from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.spray_history import SprayHistoryStore
from admapper.core.users import UsersStore
from admapper.core.workspace import WorkspaceManager
from admapper.creds.policy import (
    LockoutUserState,
    PolicyFetchResult,
    apply_lockout_states,
    filter_spray_targets,
)
from admapper.creds.spray import run_spray
from admapper.creds.variations import generate_spray_variations
from admapper.models.host import HostRecord
from admapper.models.spray import DomainLockoutPolicy, SprayAttempt
from admapper.models.user import UserRecord


def test_filter_spray_targets_lockout_buffer() -> None:
    policy = DomainLockoutPolicy(lockout_threshold=5)
    users = [
        UserRecord(username="safe", sources=["ldap"], bad_pwd_count=1, enabled=True),
        UserRecord(username="risky", sources=["ldap"], bad_pwd_count=4, enabled=True),
        UserRecord(
            username="locked",
            sources=["ldap"],
            bad_pwd_count=1,
            lockout_time=12345,
            enabled=True,
        ),
        UserRecord(username="svc$", sources=["ldap"], enabled=True),
    ]
    eligible, skipped = filter_spray_targets(users, policy)
    assert eligible == ["safe"]
    assert len(skipped) == 3


def test_generate_spray_variations_includes_company_year() -> None:
    variations = generate_spray_variations("corp.local", year=2026)
    assert "Corp2026!" in variations
    assert "Winter2026!" in variations


def test_spray_history_blocks_repeat(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    store = SprayHistoryStore(manager, "lab")
    store.add(
        SprayAttempt(password="Winter2026!", users_tested=3, hits=[], method="ldap")
    )
    assert store.password_already_sprayed("Winter2026!")


def test_run_spray_stores_hits(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("corp.local")
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[88, 389], is_domain_controller=True)]
    )
    UsersStore(manager, "lab").merge(
        [
            UserRecord(username="jsmith", sources=["ldap"], enabled=True),
            UserRecord(username="adoe", sources=["ldap"], enabled=True),
        ]
    )

    policy = DomainLockoutPolicy(lockout_threshold=0, source_host="10.0.0.1")
    states = [
        LockoutUserState(username="jsmith", bad_pwd_count=0, lockout_time=0),
        LockoutUserState(username="adoe", bad_pwd_count=0, lockout_time=0),
    ]

    with (
        patch("admapper.creds.spray.confirm", return_value=True),
        patch(
            "admapper.creds.spray.fetch_lockout_context",
            return_value=PolicyFetchResult(
                host="10.0.0.1",
                base_dn="DC=corp,DC=local",
                policy=policy,
                user_states=states,
            ),
        ),
        patch(
            "admapper.creds.spray.spray_password",
            return_value=(["jsmith"], "ldap", None),
        ),
        patch("admapper.creds.spray.print_manual_guide"),
    ):
        result = run_spray(session, "Winter2026!", method="ldap")

    assert result.hits == ["jsmith"]
    assert (tmp_path / "ws" / "lab" / "spray_history.json").is_file()
    creds = (tmp_path / "ws" / "lab" / "credentials.json").read_text(encoding="utf-8")
    assert "jsmith" in creds
    assert "Winter2026!" in creds


def test_apply_lockout_states_merges_counters() -> None:
    users = [UserRecord(username="jsmith", sources=["ldap"])]
    states = [LockoutUserState(username="jsmith", bad_pwd_count=2, lockout_time=0)]
    merged = apply_lockout_states(users, states)
    assert merged[0].bad_pwd_count == 2
