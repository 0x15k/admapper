from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from admapper.creds.policy import apply_lockout_states, fetch_lockout_context, filter_spray_targets
from admapper.graph.ops_state import collect_identity_capabilities
from admapper.models.spray import DomainLockoutPolicy
from admapper.models.user import UserRecord
from admapper.report.engagement import _load_json
from admapper.graph.ops_progress import filtered_loot_clues

from admapper.analysis.attack_readiness import build_attack_readiness
from admapper.analysis.password_rules import analyze_password_clues


def _load_lockout_policy(ws_path: Path) -> dict[str, Any] | None:
    return _load_json(ws_path / "lockout_policy.json")


def _save_lockout_policy(ws_path: Path, payload: dict[str, Any]) -> Path:
    out = ws_path / "lockout_policy.json"
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def _dc_ip_from_workspace(ws_path: Path) -> str:
    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    for host in unauth.get("hosts") or []:
        if host.get("is_domain_controller"):
            return str(host.get("address", ""))
    hosts = unauth.get("hosts") or []
    if hosts:
        return str(hosts[0].get("address", ""))
    state = _load_json(ws_path / "state.json") or {}
    return str(state.get("hosts") or "").strip()


def _base_dn_from_inventory(inv: dict[str, Any]) -> str | None:
    users = inv.get("users") or []
    for user in users:
        dn = str(user.get("dn") or "")
        if not dn:
            continue
        parts = [p for p in dn.split(",") if p.upper().startswith("DC=")]
        if parts:
            return ",".join(parts)
    return None


def _users_from_inventory(inv: dict[str, Any]) -> list[UserRecord]:
    return [UserRecord.from_dict(u) for u in inv.get("users") or []]


def _human_users(users: list[UserRecord]) -> list[UserRecord]:
    return [u for u in users if not u.is_machine_account]


def _attempts_remaining(user: UserRecord, policy: DomainLockoutPolicy) -> int | None:
    if not policy.lockout_enabled:
        return None
    if user.lockout_time and user.lockout_time != 0:
        return 0
    bad = user.bad_pwd_count if user.bad_pwd_count is not None else 0
    return max(0, policy.lockout_threshold - bad)


def _domain_user_row(user: UserRecord, policy: DomainLockoutPolicy) -> dict[str, Any]:
    remaining = _attempts_remaining(user, policy)
    flags: list[str] = []
    if user.kerberoastable:
        flags.append("kerberoast")
    if user.asrep_roastable:
        flags.append("asrep")
    if user.password_not_required:
        flags.append("pwd_not_req")
    if user.lockout_time and user.lockout_time != 0:
        flags.append("locked")
    return {
        "username": user.username,
        "enabled": user.enabled,
        "bad_pwd_count": user.bad_pwd_count,
        "attempts_remaining": remaining,
        "spn_count": len(user.spns),
        "kerberoastable": user.kerberoastable,
        "asrep_roastable": user.asrep_roastable,
        "dn": user.dn,
        "flags": flags,
    }


def _lockout_budget(users: list[UserRecord], policy: DomainLockoutPolicy) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for user in _human_users(users):
        if not user.enabled:
            continue
        remaining = _attempts_remaining(user, policy)
        rows.append(
            {
                "username": user.username,
                "bad_pwd_count": user.bad_pwd_count or 0,
                "attempts_remaining": remaining,
                "locked": bool(user.lockout_time and user.lockout_time != 0),
            }
        )
    return sorted(rows, key=lambda r: (r["attempts_remaining"] is None, r["attempts_remaining"] or 0))


def resolve_lockout_context(
    ws_path: Path,
    *,
    fetch_if_missing: bool = True,
) -> tuple[DomainLockoutPolicy, list[UserRecord], str | None]:
    """
    Load lockout policy from workspace; optionally fetch from DC when absent.
    Returns (policy, user_states_as_records, error).
    """
    inv = _load_json(ws_path / "auth_inventory.json") or {}
    users = _users_from_inventory(inv)
    cached = _load_lockout_policy(ws_path)
    policy: DomainLockoutPolicy | None = None
    error: str | None = None

    if cached:
        policy_data = cached.get("policy") or {}
        policy = DomainLockoutPolicy.from_dict(policy_data)
        error = cached.get("error")
        states = cached.get("user_states") or []
        if states and users:
            from admapper.creds.policy import LockoutUserState

            lockout_states = [
                LockoutUserState(
                    username=str(s.get("username", "")),
                    bad_pwd_count=int(s.get("bad_pwd_count", 0)),
                    lockout_time=int(s.get("lockout_time", 0)),
                )
                for s in states
            ]
            users = apply_lockout_states(users, lockout_states)
        return policy, users, error

    if not fetch_if_missing:
        return DomainLockoutPolicy(), users, None

    dc_ip = _dc_ip_from_workspace(ws_path)
    if not dc_ip:
        return DomainLockoutPolicy(), users, "no DC IP — run scan first"

    base_dn = _base_dn_from_inventory(inv)
    ctx = fetch_lockout_context(dc_ip, base_dn=base_dn)
    policy = ctx.policy or DomainLockoutPolicy(source_host=dc_ip)
    error = ctx.error
    if ctx.user_states:
        users = apply_lockout_states(users, ctx.user_states)

    payload = {
        "fetched_at": datetime.now(UTC).isoformat(),
        "host": ctx.host,
        "base_dn": ctx.base_dn,
        "error": ctx.error,
        "policy": policy.to_dict(),
        "user_states": [
            {
                "username": s.username,
                "bad_pwd_count": s.bad_pwd_count,
                "lockout_time": s.lockout_time,
            }
            for s in ctx.user_states
        ],
    }
    _save_lockout_policy(ws_path, payload)
    return policy, users, error


def build_engagement_intel(
    ws_path: Path,
    *,
    workspace: str = "",
    domain: str | None = None,
    owned_users: list[str] | None = None,
    ops_progress: object | None = None,
) -> dict[str, Any]:
    """Aggregate domain users, lockout/GPO, spray safety, and password rule analysis."""
    ws_path = Path(ws_path)
    owned = list(owned_users or [])
    inv = _load_json(ws_path / "auth_inventory.json") or {}
    domain_s = domain or str(inv.get("domain") or "")

    policy, users, lockout_error = resolve_lockout_context(ws_path, fetch_if_missing=False)
    if lockout_error is None and not _load_lockout_policy(ws_path):
        lockout_error = "sin lockout_policy.json — ejecuta enum LDAP autenticada"
    humans = _human_users(users)

    eligible, skipped = filter_spray_targets(humans, policy)
    clues = filtered_loot_clues(ws_path, ops_progress)  # type: ignore[arg-type]
    password_analysis = analyze_password_clues(clues) if clues else {
        "rules": [],
        "inferences": [],
        "transforms": [],
    }
    if ops_progress is not None and not getattr(ops_progress, "enum_users", False):
        humans = []
        eligible, skipped = [], []

    identity_capabilities: list[dict[str, Any]] = []
    if domain_s:
        identity_capabilities = collect_identity_capabilities(
            ws_path, domain=domain_s, owned_users=owned
        )

    duration_min = policy.lockout_duration_seconds // 60 if policy.lockout_duration_seconds else 0
    window_min = (
        policy.lockout_observation_window_seconds // 60
        if policy.lockout_observation_window_seconds
        else 0
    )

    attack_readiness = build_attack_readiness(
        ws_path, users=users, policy=policy, owned_users=owned
    )

    return {
        "attack_readiness": attack_readiness,
        "domain_users": [_domain_user_row(u, policy) for u in sorted(humans, key=lambda u: u.username.lower())],
        "lockout_policy": {
            "lockout_threshold": policy.lockout_threshold,
            "lockout_duration_seconds": policy.lockout_duration_seconds,
            "lockout_observation_window_seconds": policy.lockout_observation_window_seconds,
            "lockout_enabled": policy.lockout_enabled,
            "source_host": policy.source_host,
            "duration_minutes": duration_min,
            "window_minutes": window_min,
            "error": lockout_error,
        },
        "lockout_budget": _lockout_budget(users, policy),
        "spray_safety": {
            "eligible": eligible,
            "skipped": skipped,
            "eligible_count": len(eligible),
            "skipped_count": len(skipped),
        },
        "password_analysis": password_analysis,
        "identity_capabilities": identity_capabilities,
        "loot_clues": clues,
    }
