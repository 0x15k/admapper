from __future__ import annotations

from dataclasses import dataclass, field

from ldap3 import ALL, ANONYMOUS, BASE, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPException

from admapper.models.spray import DomainLockoutPolicy
from admapper.models.user import UserRecord

_LOCKOUT_ATTRS = [
    "lockoutThreshold",
    "lockoutDuration",
    "lockoutObservationWindow",
]
_USER_LOCKOUT_ATTRS = ["sAMAccountName", "badPwdCount", "lockoutTime"]


def _interval_to_seconds(value: object) -> int:
    """Convert AD large-integer interval (100-ns ticks, negative) to seconds."""
    if value is None:
        return 0
    try:
        ticks = abs(int(value))
    except (TypeError, ValueError):
        return 0
    return ticks // 10_000_000


@dataclass
class LockoutUserState:
    username: str
    bad_pwd_count: int = 0
    lockout_time: int = 0


@dataclass
class PolicyFetchResult:
    host: str
    base_dn: str | None = None
    policy: DomainLockoutPolicy | None = None
    user_states: list[LockoutUserState] = field(default_factory=list)
    error: str | None = None


def fetch_domain_lockout_policy(
    host: str,
    base_dn: str,
    *,
    port: int = 389,
    timeout: int = 10,
    use_ssl: bool = False,
) -> DomainLockoutPolicy | None:
    """Read lockout policy from the domain naming context head."""
    try:
        server = Server(host, port=port, use_ssl=use_ssl, connect_timeout=timeout, get_info=ALL)
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=timeout)
        if not conn.bind():
            return None
        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=domain)",
            search_scope=BASE,
            attributes=_LOCKOUT_ATTRS,
        )
        if not conn.entries:
            return None
        entry = conn.entries[0]
        threshold = int(entry.lockoutThreshold.value or 0) if entry.lockoutThreshold else 0
        duration = _interval_to_seconds(
            entry.lockoutDuration.value if entry.lockoutDuration else None
        )
        window = _interval_to_seconds(
            entry.lockoutObservationWindow.value if entry.lockoutObservationWindow else None
        )
        return DomainLockoutPolicy(
            lockout_threshold=threshold,
            lockout_duration_seconds=duration,
            lockout_observation_window_seconds=window,
            source_host=host,
        )
    except (LDAPException, OSError):
        return None


def fetch_user_lockout_states(
    host: str,
    base_dn: str,
    *,
    port: int = 389,
    timeout: int = 10,
    use_ssl: bool = False,
) -> list[LockoutUserState]:
    """Fetch badPwdCount / lockoutTime for human user accounts."""
    states: list[LockoutUserState] = []
    try:
        server = Server(host, port=port, use_ssl=use_ssl, connect_timeout=timeout, get_info=ALL)
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=timeout)
        if not conn.bind():
            return states
        conn.search(
            search_base=base_dn,
            search_filter="(&(objectClass=user)(objectCategory=person))",
            search_scope=SUBTREE,
            attributes=_USER_LOCKOUT_ATTRS,
        )
        for entry in conn.entries:
            username = str(entry.sAMAccountName) if entry.sAMAccountName else ""
            if not username or username.endswith("$"):
                continue
            bad = int(entry.badPwdCount.value or 0) if entry.badPwdCount else 0
            locked = int(entry.lockoutTime.value or 0) if entry.lockoutTime else 0
            states.append(
                LockoutUserState(
                    username=username,
                    bad_pwd_count=bad,
                    lockout_time=locked,
                )
            )
    except (LDAPException, OSError):
        return states
    return states


def apply_lockout_states(
    users: list[UserRecord],
    states: list[LockoutUserState],
) -> list[UserRecord]:
    """Merge LDAP lockout counters into the user inventory."""
    by_name = {s.username.lower(): s for s in states}
    updated: list[UserRecord] = []
    for user in users:
        state = by_name.get(user.username.lower())
        if state is None:
            updated.append(user)
            continue
        updated.append(
            UserRecord(
                username=user.username,
                sources=list(user.sources),
                rid=user.rid,
                description=user.description,
                dn=user.dn,
                uac=user.uac,
                spns=list(user.spns),
                asrep_roastable=user.asrep_roastable,
                kerberoastable=user.kerberoastable,
                password_not_required=user.password_not_required,
                enabled=user.enabled,
                bad_pwd_count=state.bad_pwd_count,
                lockout_time=state.lockout_time,
            )
        )
    return updated


def filter_spray_targets(
    users: list[UserRecord],
    policy: DomainLockoutPolicy,
    *,
    safety_buffer: int = 1,
) -> tuple[list[str], list[str]]:
    """
    Return (eligible_usernames, skipped_reasons).

    Skips disabled, machine accounts, currently locked, and users near lockout threshold.
    """
    eligible: list[str] = []
    skipped: list[str] = []
    threshold = policy.lockout_threshold

    for user in users:
        if user.is_machine_account:
            skipped.append(f"{user.username}: machine account")
            continue
        if not user.enabled:
            skipped.append(f"{user.username}: disabled")
            continue
        if user.lockout_time and user.lockout_time != 0:
            skipped.append(f"{user.username}: lockoutTime set (likely locked)")
            continue
        if threshold > 0 and user.bad_pwd_count is not None:
            remaining = threshold - user.bad_pwd_count
            if remaining <= safety_buffer:
                skipped.append(
                    f"{user.username}: badPwdCount={user.bad_pwd_count} "
                    f"(threshold={threshold}, buffer={safety_buffer})"
                )
                continue
        eligible.append(user.username)

    return eligible, skipped


def fetch_lockout_context(
    host: str,
    *,
    port: int = 389,
    base_dn: str | None = None,
    timeout: int = 10,
) -> PolicyFetchResult:
    """Fetch domain policy and per-user lockout counters in one LDAP session."""
    result = PolicyFetchResult(host=host)
    try:
        server = Server(host, port=port, connect_timeout=timeout, get_info=ALL)
        conn = Connection(server, authentication=ANONYMOUS, receive_timeout=timeout)
        if not conn.bind():
            result.error = conn.result.get("description", "LDAP bind failed")
            return result
        search_base = base_dn
        if not search_base and server.info:
            search_base = server.info.other.get("defaultNamingContext", [None])[0]
        if not search_base:
            result.error = "could not determine LDAP search base"
            return result
        result.base_dn = search_base
        result.policy = fetch_domain_lockout_policy(host, search_base, port=port, timeout=timeout)
        result.user_states = fetch_user_lockout_states(
            host, search_base, port=port, timeout=timeout
        )
        if result.policy is None:
            result.policy = DomainLockoutPolicy(source_host=host)
    except LDAPException as exc:
        result.error = str(exc)
    except OSError as exc:
        result.error = str(exc)
    return result
