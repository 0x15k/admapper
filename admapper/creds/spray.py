from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from admapper.stores.findings import FindingsStore
from admapper.support.output import (
    ConfirmLevel,
    confirm,
    print_info,
    print_success,
    print_table,
    print_warning,
)
from admapper.stores.spray_history import SprayHistoryStore
from admapper.stores.users import UsersStore
from admapper.creds.common import apply_cracked_credentials, pick_dc_ip
from admapper.creds.policy import (
    apply_lockout_states,
    fetch_lockout_context,
    filter_spray_targets,
)
from admapper.creds.spray_engine import spray_password
from admapper.creds.variations import generate_spray_variations
from admapper.guides.render import print_manual_guide
from admapper.models.finding import Finding, FindingSeverity
from admapper.models.spray import DomainLockoutPolicy, SprayAttempt
from admapper.models.user import UserRecord

if TYPE_CHECKING:
    from admapper.support.session import Session


@dataclass
class SprayResult:
    domain: str
    dc_ip: str
    password: str
    method: str
    users_tested: int
    hits: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    policy: DomainLockoutPolicy | None = None
    errors: list[str] = field(default_factory=list)


def _format_policy(policy: DomainLockoutPolicy) -> str:
    if not policy.lockout_enabled:
        return "lockout disabled (threshold=0)"
    duration_min = policy.lockout_duration_seconds // 60
    return (
        f"threshold={policy.lockout_threshold}, "
        f"duration={duration_min}m, "
        f"window={policy.lockout_observation_window_seconds // 60}m"
    )


def _prepare_users(
    session: Session,
    dc_ip: str,
    usernames: list[str] | None,
) -> tuple[list[str], list[str], DomainLockoutPolicy, list[str]]:
    ws_name = session.workspace.name  # type: ignore[union-attr]
    users_store = UsersStore(session.workspaces, ws_name)
    inventory = users_store.list()
    if not inventory and not usernames:
        raise ValueError("no users in workspace — run enum users first")

    ctx = fetch_lockout_context(dc_ip)
    policy = ctx.policy or DomainLockoutPolicy(source_host=dc_ip)
    if ctx.error:
        print_warning(f"lockout policy fetch partial: {ctx.error}")

    if ctx.user_states:
        merged = apply_lockout_states(inventory, ctx.user_states)
        users_store.save_all(merged)
        inventory = merged

    if usernames:
        by_name = {u.username.lower(): u for u in inventory}
        selected = []
        for name in usernames:
            record = by_name.get(name.lower())
            if record:
                selected.append(record)
            else:
                selected.append(UserRecord(username=name, sources=["manual"]))
        eligible, skipped = filter_spray_targets(selected, policy)
        return eligible, skipped, policy, []

    eligible, skipped = filter_spray_targets(inventory, policy)
    return eligible, skipped, policy, skipped


def run_spray(
    session: Session,
    password: str,
    *,
    usernames: list[str] | None = None,
    method: str = "auto",
    dry_run: bool = False,
    force: bool = False,
    skip_confirm: bool = False,
) -> SprayResult:
    """Phase 6 — password spraying (one password, many users)."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before spray")

    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC with LDAP/Kerberos — run start_unauth first")

    # Blank passwords are allowed only in LAB opsec mode and for PASSWD_NOTREQD accounts.
    is_blank_spray = password == ""

    history = SprayHistoryStore(session.workspaces, session.workspace.name)
    if history.password_already_sprayed(password) and not (force or is_blank_spray):
        raise ValueError(
            "password already sprayed in this workspace — use --force to repeat (lockout risk)"
        )

    eligible, skipped, policy, _ = _prepare_users(session, dc_ip, usernames)

    # LAB mode: restrict blank spray to PASSWD_NOTREQD accounts only
    if is_blank_spray:
        if session.opsec_profile.name.lower() != "lab":
            raise ValueError("blank-password spray is only allowed in LAB opsec mode")
        users_store = UsersStore(session.workspaces, session.workspace.name)
        inventory = users_store.list()
        by_name = {u.username.lower(): u for u in inventory}
        blank_eligible = [
            u
            for u in eligible
            if "PASSWD_NOTREQD" in by_name.get(u.lower(), UserRecord(username=u)).flags
        ]
        if not blank_eligible:
            print_warning("no PASSWD_NOTREQD users eligible for blank-password spray")
            return SprayResult(
                domain=domain,
                dc_ip=dc_ip,
                password="",
                method="blank-skipped",
                users_tested=0,
                skipped=skipped,
                policy=policy,
            )
        print_info(
            "LAB mode — blank-password spray against "
            f"{len(blank_eligible)} PASSWD_NOTREQD account(s)"
        )
        eligible = blank_eligible

    policy_text = _format_policy(policy)
    confirm_msg = f"Spray password against {len(eligible)} users @ {dc_ip}? Policy: {policy_text}"
    if not skip_confirm and not confirm(
        confirm_msg,
        level=ConfirmLevel.DANGER if policy.lockout_enabled else ConfirmLevel.WARN,
        mode_auto=session.mode.value == "auto",
        mode_manual=session.mode.value == "manual",
    ):
        print_warning("Spray cancelled")
        return SprayResult(
            domain=domain,
            dc_ip=dc_ip,
            password=password,
            method="cancelled",
            users_tested=0,
            skipped=skipped,
            policy=policy,
        )

    print_info(f"Phase 6 — Password spray @ {dc_ip} ({policy_text})")
    if skipped:
        print_warning(f"skipped {len(skipped)} users (lockout safety)")

    if dry_run:
        print_info(f"dry-run: would test {len(eligible)} users with method={method}")
        return SprayResult(
            domain=domain,
            dc_ip=dc_ip,
            password=password,
            method=method,
            users_tested=len(eligible),
            skipped=skipped,
            policy=policy,
        )

    hits, method_used, error = spray_password(
        dc_ip,
        domain,
        eligible,
        password,
        method=method,
    )
    result = SprayResult(
        domain=domain,
        dc_ip=dc_ip,
        password=password,
        method=method_used,
        users_tested=len(eligible),
        hits=hits,
        skipped=skipped,
        policy=policy,
    )
    if error:
        result.errors.append(error)
        print_warning(error)

    if hits:
        rows = [[user, password] for user in hits]
        print_table("Valid credentials", ["user", "password"], rows)
        cracked = {f"{user}@{domain}": password for user in hits}
        apply_cracked_credentials(session, domain, cracked, source="spray")
        for user in hits:
            print_success(f"valid: {domain}\\{user}:{password}")
    else:
        print_warning("no valid credentials found for this password")

    history.add(
        SprayAttempt(
            password=password,
            users_tested=len(eligible),
            hits=hits,
            method=method_used,
        )
    )
    print_success("spray logged → spray_history.json")

    ws_name = session.workspace.name
    findings_store = FindingsStore(session.workspaces, ws_name)
    finding_rows = [
        Finding(
            key="spray_attempt",
            title=f"Password spray attempted ({len(eligible)} users)",
            severity=FindingSeverity.INFO,
            source="spray",
            detail=f"password={password[:3]}***, method={method_used}, policy={policy_text}",
            mitre_id="T1110.003",
        )
    ]
    if hits:
        finding_rows.append(
            Finding(
                key="spray_valid_credential",
                title=f"Password spray hit ({len(hits)} accounts)",
                severity=FindingSeverity.HIGH,
                source="spray",
                detail=f"users={', '.join(hits)}",
                mitre_id="T1078",
            )
        )
    findings_store.merge(finding_rows)

    report_path = session.workspaces.path_for(ws_name) / "spray_report.json"
    report_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "dc_ip": dc_ip,
                "password_redacted": password[:2] + "***",
                "method": method_used,
                "users_tested": len(eligible),
                "hits": hits,
                "skipped_count": len(skipped),
                "policy": policy.to_dict() if policy else None,
                "errors": result.errors,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print_manual_guide("passwordspray", session=session)
    return result


def run_spray_variations(
    session: Session,
    *,
    usernames: list[str] | None = None,
    method: str = "auto",
    dry_run: bool = False,
    force: bool = False,
    max_passwords: int = 12,
) -> list[SprayResult]:
    """Spray auto-generated seasonal/company password variations."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before spray variations")

    variations = generate_spray_variations(domain)[:max_passwords]
    history = SprayHistoryStore(session.workspaces, session.workspace.name)
    pending = [p for p in variations if force or not history.password_already_sprayed(p)]
    if not pending:
        raise ValueError("all variation passwords already sprayed — use --force")

    if not confirm(
        f"Spray {len(pending)} password variations against {domain}?",
        level=ConfirmLevel.DANGER,
        mode_auto=session.mode.value == "auto",
        mode_manual=session.mode.value == "manual",
    ):
        print_warning("Variation spray cancelled")
        return []

    results: list[SprayResult] = []
    for idx, password in enumerate(pending, start=1):
        print_info(f"variation {idx}/{len(pending)}: {password}")
        try:
            result = run_spray(
                session,
                password,
                usernames=usernames,
                method=method,
                dry_run=dry_run,
                force=force,
                skip_confirm=True,
            )
        except ValueError as exc:
            print_warning(str(exc))
            continue
        results.append(result)
        if result.hits:
            print_success("hit found — stopping variation spray early")
            break

    # LAB mode: also attempt blank password against PASSWD_NOTREQD accounts
    if session.opsec_profile.name.lower() == "lab" and (
        not results or not any(r.hits for r in results)
    ):
        print_info("LAB opsec — attempting blank password against PASSWD_NOTREQD accounts")
        try:
            blank_result = run_spray(
                session,
                "",
                usernames=usernames,
                method="ldap",
                dry_run=dry_run,
                force=force,
                skip_confirm=True,
            )
            results.append(blank_result)
        except ValueError as exc:
            print_warning(str(exc))

    return results
