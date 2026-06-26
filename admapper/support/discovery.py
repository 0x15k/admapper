from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.stores.hosts import HostsStore
from admapper.support.output import print_info, print_success
from admapper.recon.dns import dn_to_domain, infer_domain_from_hostname, reverse_ptr

if TYPE_CHECKING:
    from admapper.support.session import Session


def default_workspace_name(host: str) -> str:
    """Derive a stable workspace name from a target IP/CIDR."""
    token = re.sub(r"[^a-zA-Z0-9]+", "-", host.strip()).strip("-").lower()
    return f"target-{token}" if token else "default"


def _load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_domain(session: Session) -> str | None:
    """Infer AD DNS domain from session state or prior recon artefacts."""
    if session.workspace is None:
        return None
    if session.workspace.domain:
        return session.workspace.domain

    ws_path = session.workspaces.path_for(session.workspace.name)

    unauth = _load_json(ws_path / "unauth_scan.json")
    if unauth and unauth.get("domain"):
        return str(unauth["domain"])

    findings = _load_json(ws_path / "findings.json")
    for item in (findings or {}).get("findings") or []:
        key = str(item.get("key") or "")
        if key.startswith("ldap_anonymous"):
            domain = dn_to_domain(str(item.get("detail") or ""))
            if domain:
                return domain

    for artefact in ("auth_inventory.json", "graph.json"):
        data = _load_json(ws_path / artefact)
        if not data:
            continue
        raw = data.get("domain")
        if raw:
            return str(raw).lower()

    for host in HostsStore(session.workspaces, session.workspace.name).list():
        hostname = host.hostname or reverse_ptr(host.address)
        if hostname:
            domain = infer_domain_from_hostname(hostname)
            if domain:
                return domain

    return None


def ensure_domain(session: Session, *, announce: bool = True) -> str:
    """Resolve domain from recon and persist it on the workspace."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = resolve_domain(session)
    if not domain:
        raise ValueError(
            "domain not discovered — run start_unauth against the AD host first"
        )

    if session.workspace.domain != domain:
        session.set_domain(domain)
        if announce:
            print_success(f"domain inferred: {domain}")
    elif announce and session.workspace.domain:
        print_info(f"domain: {session.workspace.domain}")

    return session.workspace.domain
