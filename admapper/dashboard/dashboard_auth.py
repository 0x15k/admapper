"""Dashboard UI credential verification."""

from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.support.output import print_success
from admapper.creds.common import pick_dc_ip
from admapper.creds.time_sync import ensure_dc_clock
from admapper.creds.verify import run_credential_verify
from admapper.escalate.analyze import mark_user_owned, set_pivot_user
from admapper.models.credential import Credential, CredentialStatus

if TYPE_CHECKING:
    from admapper.support.session import Session


def run_dashboard_credential_auth(
    session: Session,
    *,
    username: str,
    password: str,
    domain: str | None = None,
) -> Credential:
    """Add (or refresh) and verify exactly the credential the operator submitted."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    from admapper.support.discovery import ensure_domain
    from admapper.recon.ldap_probe import discover_domain_from_bind

    resolved_domain = domain or session.workspace.domain
    if not resolved_domain:
        target = _workspace_target_ip(session)
        resolved_domain = discover_domain_from_bind(
            target,
            username.strip(),
            password,
            domain_hint=domain,
        )
        if resolved_domain:
            session.set_domain(resolved_domain)
            print_success(f"domain inferred from LDAP bind: {resolved_domain}")
    if not resolved_domain:
        resolved_domain = ensure_domain(session, announce=False)

    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("sin DC — escanea el objetivo primero")

    store = session.credentials
    if store is None:
        raise RuntimeError("credential store unavailable")

    ws_path = session.workspaces.path_for(session.workspace.name)
    ensure_dc_clock(dc_ip, ws_path=ws_path)

    user_key = username.strip().lower()
    existing = next((c for c in store.list() if c.username.lower() == user_key), None)
    if existing is not None:
        store.remove(existing.id)
    cred = store.add(username.strip(), password, domain=resolved_domain, source="dashboard")

    result = run_credential_verify(session, cred.id)
    verified = result.credential
    if verified.status != CredentialStatus.VALID:
        raise ValueError(f"invalid credential for {username}")

    mark_user_owned(session, verified.username, refresh=True)
    set_pivot_user(session, verified.username)
    print_success(f"Valid credential: {verified.display_user()}")
    return verified


def _workspace_target_ip(session: Session) -> str:
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    hosts = (session.workspace.hosts or "").strip()
    if hosts:
        return hosts.split()[0]
    from admapper.stores.hosts import HostsStore

    for h in HostsStore(session.workspaces, session.workspace.name).list():
        if h.address:
            return h.address
    raise ValueError("no target IP set")
