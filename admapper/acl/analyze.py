from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from admapper.acl.enum import (
    build_acl_targets,
    fetch_security_descriptor,
    resolve_principal_context,
)
from admapper.acl.parse import owner_abuse_right, parse_security_descriptor
from admapper.acl.rights import abuse_right
from admapper.auth.ldap_session import open_ldap_session
from admapper.core.auth_inventory import AuthInventoryStore
from admapper.core.graph import GraphStore
from admapper.core.output import print_success, print_table, print_warning
from admapper.creds.common import pick_dc_ip
from admapper.guides.render import print_manual_guide
from admapper.models.ad_object import AclAbuseFinding
from admapper.models.credential import Credential, CredentialStatus

if TYPE_CHECKING:
    from admapper.core.session import Session


@dataclass
class AclAnalysisResult:
    findings: list[AclAbuseFinding] = field(default_factory=list)
    findings_path: str | None = None
    graph_path: str | None = None
    errors: list[str] = field(default_factory=list)


def _pick_credential(session: Session, cred_id: str | None) -> Credential:
    store = session.credentials
    if store is None:
        raise RuntimeError("credential store unavailable")
    creds = store.list()
    if not creds:
        raise ValueError("no credentials — add with creds add or run start_auth")

    if cred_id:
        cred = next((c for c in creds if c.id == cred_id), None)
        if cred is None:
            raise ValueError(f"credential not found: {cred_id}")
        return cred

    owned = {u.lower() for u in (session.workspace.owned_users if session.workspace else [])}
    for preferred in (CredentialStatus.VALID, CredentialStatus.UNVERIFIED):
        for cred in creds:
            if cred.status == preferred and cred.secret and cred.username.lower() in owned:
                return cred
    for preferred in (CredentialStatus.VALID, CredentialStatus.UNVERIFIED):
        for cred in creds:
            if cred.status == preferred and cred.secret:
                return cred
    raise ValueError("no usable credential for ACL enum")


def _load_member_of(session: Session) -> list[str]:
    ws_name = session.workspace.name  # type: ignore[union-attr]
    scan_path = session.workspaces.path_for(ws_name) / "auth_scan.json"
    if scan_path.is_file():
        data = json.loads(scan_path.read_text(encoding="utf-8"))
        return list(data.get("member_of") or [])
    return []


def _match_findings(
    *,
    principal: Any,
    owned_username: str,
    target: Any,
    parsed_sd: Any,
) -> list[AclAbuseFinding]:
    findings: list[AclAbuseFinding] = []
    principal_sids = principal.all_sids

    owner_right = owner_abuse_right(parsed_sd.owner_sid, principal_sids)
    if owner_right:
        meta = abuse_right(owner_right)
        via = principal.sid_to_name.get(parsed_sd.owner_sid, owned_username)
        findings.append(
            AclAbuseFinding(
                right=owner_right,
                principal=owned_username,
                trustee_sid=parsed_sd.owner_sid or "",
                trustee_name=via,
                target_dn=target.dn,
                target_name=target.name,
                target_type=target.object_type,
                severity=meta.severity,
                mitre_id=meta.mitre_id,
                summary=meta.exploit_summary,
                manual_commands=list(meta.manual_commands),
            )
        )

    for ace in parsed_sd.aces:
        if ace.trustee_sid not in principal_sids:
            continue
        via_name = principal.sid_to_name.get(ace.trustee_sid, ace.trustee_sid)
        for right in ace.rights:
            if right == "dcsync_partial":
                continue
            meta = abuse_right(right)
            findings.append(
                AclAbuseFinding(
                    right=right,
                    principal=owned_username,
                    trustee_sid=ace.trustee_sid,
                    trustee_name=via_name,
                    target_dn=target.dn,
                    target_name=target.name,
                    target_type=target.object_type,
                    severity=meta.severity,
                    mitre_id=meta.mitre_id,
                    summary=meta.exploit_summary,
                    manual_commands=list(meta.manual_commands),
                )
            )
    return findings


def _enrich_graph_with_acls(
    graph_store: GraphStore,
    domain: str,
    owned_user: str,
    findings: list[AclAbuseFinding],
) -> None:
    graph = graph_store.load()
    nodes = list(graph.get("nodes", []))
    edges = list(graph.get("edges", []))
    edge_ids = {e.get("id") for e in edges}

    source_id = f"user:{owned_user.lower()}@{domain.lower()}"

    def ensure_node(node_id: str, ntype: str, name: str) -> None:
        if any(n.get("id") == node_id for n in nodes):
            return
        nodes.append(
            {
                "id": node_id,
                "type": ntype,
                "name": name,
                "domain": domain.lower(),
                "owned": False,
            }
        )

    for finding in findings:
        if finding.target_type == "user":
            target_id = f"user:{finding.target_name.lower()}@{domain.lower()}"
        elif finding.target_type == "group":
            target_id = f"group:{finding.target_name.lower()}@{domain.lower()}"
        elif finding.target_type == "computer":
            target_id = f"computer:{finding.target_name.lower()}.{domain.lower()}"
        elif finding.target_type == "domain":
            target_id = f"domain:{domain.lower()}"
        else:
            target_id = f"object:{finding.target_name.lower()}@{domain.lower()}"

        ensure_node(target_id, finding.target_type, finding.target_name)
        edge_id = f"{source_id}->{finding.right}->{target_id}"
        if edge_id in edge_ids:
            continue
        edges.append(
            {
                "id": edge_id,
                "source": source_id,
                "target": target_id,
                "type": finding.right,
                "severity": finding.severity,
                "mitre_id": finding.mitre_id,
            }
        )
        edge_ids.add(edge_id)

    graph["nodes"] = nodes
    graph["edges"] = edges
    graph_store.save(graph)


def run_acl_analysis(session: Session, *, cred_id: str | None = None) -> AclAnalysisResult:
    """Phase 10 — enumerate ACLs and surface abuse opportunities for owned principals."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before acls")

    owned_users = session.workspace.owned_users
    if not owned_users:
        print_warning("no owned users — run start_auth first for best results")

    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC — run start_unauth first")

    cred = _pick_credential(session, cred_id)
    ws_name = session.workspace.name

    from admapper.core.verbosity import print_phase

    print_phase(f"Phase 10 — ACL enumeration @ {dc_ip} as {cred.display_user()}")

    ws_path = str(session.workspaces.path_for(ws_name))
    ldap_session, err = open_ldap_session(dc_ip, cred, domain, ws_path=ws_path)
    if ldap_session is None:
        raise ValueError(err or "LDAP bind failed")

    inventory_store = AuthInventoryStore(session.workspaces, ws_name)
    inventory = inventory_store.load()

    result = AclAnalysisResult()
    all_findings: list[AclAbuseFinding] = []

    principals = owned_users or [cred.username]
    member_of = _load_member_of(session)

    try:
        for owned in principals:
            principal = resolve_principal_context(
                ldap_session,
                owned,
                member_of=member_of if owned.lower() == cred.username.lower() else None,
            )
            if principal is None:
                result.errors.append(f"could not resolve SID for {owned}")
                continue

            targets = build_acl_targets(ldap_session, inventory)
            from admapper.core.verbosity import quiet_info

            quiet_info(f"scanning {len(targets)} objects for ACL abuse via {owned}")

            for target in targets:
                try:
                    raw_sd = fetch_security_descriptor(ldap_session, target.dn)
                except Exception as exc:
                    result.errors.append(f"{target.dn}: {exc}")
                    continue
                if not raw_sd:
                    continue
                try:
                    parsed = parse_security_descriptor(
                        raw_sd,
                        object_classes=target.object_classes,
                    )
                except ImportError as exc:
                    raise ValueError(str(exc)) from exc
                except Exception as exc:
                    result.errors.append(f"parse {target.dn}: {exc}")
                    continue

                matched = _match_findings(
                    principal=principal,
                    owned_username=owned,
                    target=target,
                    parsed_sd=parsed,
                )
                all_findings.extend(matched)
    finally:
        ldap_session.close()

    for idx, finding in enumerate(all_findings, start=1):
        finding.id = f"acl-{idx:03d}"

    result.findings = all_findings
    findings_path = session.workspaces.path_for(ws_name) / "acl_findings.json"
    payload = {
        "domain": domain,
        "owned_users": principals,
        "finding_count": len(all_findings),
        "findings": [f.to_dict() for f in all_findings],
        "errors": result.errors,
    }
    findings_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result.findings_path = str(findings_path)

    if all_findings and principals:
        graph_store = GraphStore(session.workspaces, ws_name)
        _enrich_graph_with_acls(graph_store, domain, principals[0], all_findings)
        result.graph_path = str(graph_store.path)
        print_success("graph updated with ACL edges → graph.json")

    from admapper.core.verbosity import is_verbose

    if all_findings and is_verbose():
        rows = [
            [
                f.id,
                f.principal,
                f.right,
                f.target_name,
                f.severity,
            ]
            for f in all_findings[:20]
        ]
        print_table(
            "ACL abuse opportunities",
            ["id", "principal", "right", "target", "severity"],
            rows,
        )
    elif not all_findings:
        print_warning("no ACL abuse paths found for owned principals")

    from admapper.core.verbosity import quiet_success

    quiet_success("ACL findings saved → acl_findings.json")
    print_manual_guide("acl_abuse", session=session)
    return result


def get_acl_finding(session: Session, finding_id: str) -> dict[str, Any] | None:
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    path = session.workspaces.path_for(session.workspace.name) / "acl_findings.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data.get("findings", []):
        if str(item.get("id")) == finding_id:
            return item
    return None
