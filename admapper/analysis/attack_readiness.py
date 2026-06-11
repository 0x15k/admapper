from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from admapper.creds.kerberos_skew import load_workspace_clock_skew
from admapper.creds.policy import apply_lockout_states, fetch_lockout_context, filter_spray_targets
from admapper.models.spray import DomainLockoutPolicy
from admapper.models.user import UserRecord
from admapper.report.engagement import _load_json
from admapper.report.engagement_map import loot_clue_rows


@dataclass
class PrerequisiteCheck:
    key: str
    label: str
    met: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "met": self.met,
            "detail": self.detail,
        }


@dataclass
class AttackVector:
    attack_id: str
    title: str
    phase: str
    ready: bool
    prerequisites: list[PrerequisiteCheck]
    targets: list[dict[str, Any]]
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        missing = [p.label for p in self.prerequisites if not p.met]
        return {
            "attack_id": self.attack_id,
            "title": self.title,
            "phase": self.phase,
            "ready": self.ready,
            "prerequisites": [p.to_dict() for p in self.prerequisites],
            "targets": self.targets,
            "missing": missing,
            "note": self.note,
        }


def _open_ports(ws_path: Path) -> set[int]:
    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    ports: set[int] = set()
    for host in unauth.get("hosts") or []:
        for p in host.get("open_ports") or []:
            try:
                ports.add(int(p))
            except (TypeError, ValueError):
                continue
    return ports


def _valid_cred_users(ws_path: Path) -> set[str]:
    creds = (_load_json(ws_path / "credentials.json") or {}).get("credentials") or []
    return {
        str(c.get("username", "")).lower()
        for c in creds
        if str(c.get("status")) == "valid"
    }


def _human_users(users: list[UserRecord]) -> list[UserRecord]:
    return [u for u in users if not u.is_machine_account]


def _attempts_remaining(user: UserRecord | None, policy: DomainLockoutPolicy) -> int | None:
    if user is None:
        return None
    if not policy.lockout_enabled and policy.lockout_threshold <= 0:
        return None
    if user.lockout_time and user.lockout_time != 0:
        return 0
    bad = user.bad_pwd_count if user.bad_pwd_count is not None else 0
    return max(0, policy.lockout_threshold - bad)


def _port_check(ports: set[int], port: int, label: str) -> PrerequisiteCheck:
    met = port in ports
    return PrerequisiteCheck(
        key=f"port_{port}",
        label=label,
        met=met,
        detail=f"TCP/{port} {'abierto' if met else 'no visto en scan'}",
    )


def _lockout_loaded(ws_path: Path, policy: DomainLockoutPolicy) -> PrerequisiteCheck:
    cached = _load_json(ws_path / "lockout_policy.json")
    met = bool(cached and (policy.lockout_threshold or cached.get("policy")))
    return PrerequisiteCheck(
        key="lockout_policy",
        label="Política de bloqueo (GPO) consultada",
        met=met,
        detail="enum LDAP persiste lockout_policy.json" if not met else f"umbral={policy.lockout_threshold}",
    )


def _kerberos_clock(ws_path: Path) -> PrerequisiteCheck:
    skew = load_workspace_clock_skew(ws_path)
    return PrerequisiteCheck(
        key="kerberos_clock",
        label="Reloj Kerberos alineado o skew guardado",
        met=bool(skew),
        detail=skew or "sincroniza reloj con DC o --clock-skew",
    )


def resolve_lockout_context(
    ws_path: Path,
    *,
    fetch_if_missing: bool = True,
) -> tuple[DomainLockoutPolicy, list[UserRecord], str | None]:
    """Load lockout policy from workspace; optionally fetch from DC when absent."""
    from datetime import UTC, datetime

    inv = _load_json(ws_path / "auth_inventory.json") or {}
    users = [UserRecord.from_dict(u) for u in inv.get("users") or []]
    cached = _load_json(ws_path / "lockout_policy.json")
    error: str | None = None

    if cached:
        policy = DomainLockoutPolicy.from_dict(cached.get("policy") or {})
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

    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    dc_ip = ""
    for host in unauth.get("hosts") or []:
        if host.get("is_domain_controller"):
            dc_ip = str(host.get("address", ""))
            break
    if not dc_ip:
        return DomainLockoutPolicy(), users, "no DC IP — run scan first"

    base_dn = None
    for user in inv.get("users") or []:
        dn = str(user.get("dn") or "")
        parts = [p for p in dn.split(",") if p.upper().startswith("DC=")]
        if parts:
            base_dn = ",".join(parts)
            break

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
    out = Path(ws_path) / "lockout_policy.json"
    out.write_text(__import__("json").dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return policy, users, error


def build_attack_readiness(
    ws_path: Path,
    *,
    users: list[UserRecord],
    policy: DomainLockoutPolicy,
    owned_users: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Full AD pentest attack-vector prerequisite matrix (generic, not lab-specific)."""
    from admapper.analysis.attack_vector_catalog import WorkspaceContext, build_all_attack_vectors

    ctx = WorkspaceContext.build(ws_path, users=users, policy=policy, owned_users=owned_users)
    return [v.to_dict() for v in build_all_attack_vectors(ctx)]


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
