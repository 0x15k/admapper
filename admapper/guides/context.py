from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from admapper.core.hosts import HostsStore
from admapper.creds.common import pick_dc_ip
from admapper.models.credential import CredentialStatus

if TYPE_CHECKING:
    from admapper.core.session import Session


def domain_to_base_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


@dataclass
class GuideContext:
    domain: str | None = None
    dc_ip: str | None = None
    dc_host: str | None = None
    base_dn: str | None = None
    username: str | None = None
    password: str | None = None

    @property
    def is_contextualized(self) -> bool:
        return bool(self.domain and self.dc_ip)


def build_guide_context(session: Session) -> GuideContext:
    """Build substitution values from the active workspace."""
    ctx = GuideContext()
    if session.workspace is None:
        return ctx

    domain = session.workspace.domain
    if domain:
        ctx.domain = domain
        ctx.base_dn = domain_to_base_dn(domain)

    ctx.dc_ip = pick_dc_ip(session)

    ws_path = session.workspaces.path_for(session.workspace.name)
    inv_path = ws_path / "auth_inventory.json"
    if inv_path.is_file():
        inv = json.loads(inv_path.read_text(encoding="utf-8"))
        for computer in inv.get("computers") or []:
            if computer.get("unconstrained_delegation") or str(computer.get("name", "")).upper().startswith(
                "DC"
            ):
                ctx.dc_host = computer.get("dns_host") or computer.get("name")
                break
        if not ctx.dc_host:
            computers = inv.get("computers") or []
            if computers:
                first = computers[0]
                ctx.dc_host = first.get("dns_host") or first.get("name")

    if not ctx.dc_host:
        for host in HostsStore(session.workspaces, session.workspace.name).list():
            if host.is_domain_controller:
                ctx.dc_host = host.hostname or host.address
                break

    owned = {u.lower() for u in session.workspace.owned_users}
    store = session.credentials
    if store:
        for preferred in (CredentialStatus.VALID, CredentialStatus.UNVERIFIED):
            for cred in store.list():
                if cred.status != preferred or not cred.secret:
                    continue
                if owned and cred.username.lower() not in owned:
                    continue
                ctx.username = cred.username
                ctx.password = cred.secret
                if not ctx.domain and cred.domain:
                    ctx.domain = cred.domain
                    ctx.base_dn = domain_to_base_dn(cred.domain)
                break
            if ctx.username:
                break

    return ctx


def contextualize_text(text: str, ctx: GuideContext) -> str:
    """Replace generic placeholders with engagement-specific values."""
    domain = ctx.domain or "<domain>"
    dc_ip = ctx.dc_ip or "<dc_ip>"
    dc_host = ctx.dc_host or (ctx.dc_ip if ctx.dc_ip else "<dc_name>")
    base_dn = ctx.base_dn or "<base_dn>"
    user = ctx.username or "<username>"
    password = ctx.password or "<password>"

    out = text
    replacements: list[tuple[str, str]] = [
        ("corp.local/user:pass@", f"{domain}/{user}:{password}@"),
        ("corp.local/user:pass", f"{domain}/{user}:{password}"),
        ("corp.local/", f"{domain}/"),
        ("user@corp.local", f"{user}@{domain}"),
        ("user@domain", f"{user}@{domain}"),
        ("DC=corp,DC=local", base_dn),
        ("corp.local", domain),
        ("<BASE_DN>", base_dn),
        ("<DC_IP>", dc_ip),
        ("<DC>", dc_host),
        ("<host>", dc_ip),
        ("<USER>", user),
        ("<PASS>", password),
        ("<listener>", dc_host),
        ("corp-DC01-CA", f"{domain.split('.')[0] if '.' in domain else domain}-DC01-CA" if domain != "<domain>" else "<ca_name>"),
        ("<CA>", f"{domain.split('.')[0] if '.' in domain else domain}-DC01-CA" if domain != "<domain>" else "<ca_name>"),
    ]

    seen: set[str] = set()
    for old, new in replacements:
        if old in seen or old == new:
            continue
        seen.add(old)
        out = out.replace(old, new)

    return out
