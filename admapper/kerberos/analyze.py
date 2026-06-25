from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from admapper.core.graph import GraphStore
from admapper.core.output import print_info, print_success, print_table, print_warning
from admapper.guides.render import print_manual_guide
from admapper.kerberos.catalog import technique_meta
from admapper.models.kerberos_op import KerberosOpportunity

if TYPE_CHECKING:
    from admapper.core.session import Session

_BACKUP_OPERATORS = "backup operators"


def _dn_to_sam(dn: str) -> str:
    match = re.search(r"CN=([^,]+)", dn, re.IGNORECASE)
    return match.group(1) if match else dn


def _owned_set(session: Session) -> set[str]:
    if session.workspace is None:
        return set()
    return {u.lower() for u in session.workspace.owned_users}


def _load_json(path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _opportunity(
    *,
    technique: str,
    source_object: str,
    source_type: str,
    detail: str,
    target: str | None = None,
    targets: list[str] | None = None,
    owned_relevant: bool = False,
) -> KerberosOpportunity:
    meta = technique_meta(technique)
    return KerberosOpportunity(
        technique=technique,
        title=meta.title,
        severity=meta.severity,
        mitre_id=meta.mitre_id,
        source_object=source_object,
        source_type=source_type,
        target=target,
        targets=list(targets or []),
        summary=meta.summary,
        detail=detail,
        owned_relevant=owned_relevant,
        manual_commands=list(meta.manual_commands),
        requires_external_listener=technique
        in {"unconstrained_delegation", "delegation_coerce_capture"},
    )


def _from_delegations(
    delegations: list[dict[str, Any]],
    owned: set[str],
) -> list[KerberosOpportunity]:
    ops: list[KerberosOpportunity] = []
    for item in delegations:
        name = str(item.get("object_name", ""))
        obj_type = str(item.get("object_type", "user"))
        dtype = str(item.get("delegation_type", ""))
        targets = [str(t) for t in item.get("targets") or []]
        owned_rel = name.lower() in owned

        if dtype == "unconstrained":
            ops.append(
                _opportunity(
                    technique="unconstrained_delegation",
                    source_object=name,
                    source_type=obj_type,
                    detail=f"{obj_type} {name} trusts this host for unconstrained delegation",
                    owned_relevant=owned_rel,
                )
            )
        elif dtype == "constrained_pt":
            ops.append(
                _opportunity(
                    technique="constrained_pt",
                    source_object=name,
                    source_type=obj_type,
                    detail="TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION + AllowedToDelegateTo",
                    targets=targets,
                    target=targets[0] if targets else None,
                    owned_relevant=owned_rel,
                )
            )
        elif dtype == "constrained":
            ops.append(
                _opportunity(
                    technique="constrained_delegation",
                    source_object=name,
                    source_type=obj_type,
                    detail=f"AllowedToDelegateTo: {', '.join(targets[:3])}",
                    targets=targets,
                    target=targets[0] if targets else None,
                    owned_relevant=owned_rel,
                )
            )
        elif dtype == "rbcd":
            ops.append(
                _opportunity(
                    technique="rbcd",
                    source_object=name,
                    source_type=obj_type,
                    detail="msDS-AllowedToActOnBehalfOfOtherIdentity configured",
                    targets=targets,
                    owned_relevant=owned_rel,
                )
            )
    return ops


def _from_acl_findings(
    findings: list[dict[str, Any]],
    owned: set[str],
) -> list[KerberosOpportunity]:
    ops: list[KerberosOpportunity] = []
    for item in findings:
        principal = str(item.get("principal", "")).lower()
        if principal not in owned:
            continue
        right = str(item.get("right", ""))
        target_name = str(item.get("target_name", ""))
        target_type = str(item.get("target_type", ""))

        if right in {"genericwrite", "genericall"} and target_type in {"user", "computer"}:
            ops.append(
                _opportunity(
                    technique="shadow_credentials",
                    source_object=principal,
                    source_type="user",
                    target=target_name,
                    detail=f"{right} on {target_type} {target_name} — AddKeyCredentialLink",
                    owned_relevant=True,
                )
            )
        if right in {"genericwrite", "genericall", "writedacl"} and target_type == "computer":
            ops.append(
                _opportunity(
                    technique="rbcd",
                    source_object=principal,
                    source_type="user",
                    target=target_name,
                    detail=f"{right} on computer {target_name} — configure AllowedToAct",
                    owned_relevant=True,
                )
            )
    return ops


def _from_backup_operators(
    groups: list[dict[str, Any]],
    owned: set[str],
) -> list[KerberosOpportunity]:
    ops: list[KerberosOpportunity] = []
    bo = next(
        (g for g in groups if str(g.get("name", "")).lower() == _BACKUP_OPERATORS),
        None,
    )
    if not bo:
        return ops

    members = [_dn_to_sam(str(m)) for m in bo.get("members") or []]
    for member in members:
        if member.lower() in owned:
            ops.append(
                _opportunity(
                    technique="backup_operators",
                    source_object=member,
                    source_type="user",
                    detail="Member of Backup Operators — registry hive access on DCs",
                    owned_relevant=True,
                )
            )
    if members and not any(m.lower() in owned for m in members):
        ops.append(
            _opportunity(
                technique="backup_operators",
                source_object="Backup Operators",
                source_type="group",
                detail=f"{len(members)} member(s) — hunt AddMember / membership paths",
                targets=members[:10],
                owned_relevant=False,
            )
        )
    return ops


def _from_computers(computers: list[dict[str, Any]]) -> list[KerberosOpportunity]:
    ops: list[KerberosOpportunity] = []
    for computer in computers[:100]:
        name = str(computer.get("name", ""))
        if not name:
            continue
        if computer.get("unconstrained_delegation"):
            continue  # already covered via delegations
        ops.append(
            _opportunity(
                technique="timeroast",
                source_object=name,
                source_type="computer",
                detail="Machine account candidate for timeroasting (pwdLastSet-derived keys)",
                owned_relevant=False,
            )
        )
    return ops


def _enrich_graph(
    graph_store: GraphStore,
    domain: str,
    opportunities: list[KerberosOpportunity],
) -> None:
    graph = graph_store.load()
    nodes = list(graph.get("nodes", []))
    edges = list(graph.get("edges", []))
    edge_ids = {e.get("id") for e in edges}

    for op in opportunities:
        if not op.owned_relevant:
            continue
        if op.source_type == "user":
            source_id = f"user:{op.source_object.lower()}@{domain.lower()}"
        elif op.source_type == "computer":
            source_id = f"computer:{op.source_object.lower()}.{domain.lower()}"
        else:
            continue

        if op.target:
            if op.technique in {"shadow_credentials", "constrained_delegation", "constrained_pt"}:
                target_id = f"user:{op.target.lower()}@{domain.lower()}"
            else:
                target_id = f"computer:{op.target.lower()}.{domain.lower()}"
        else:
            target_id = source_id

        edge_id = f"{source_id}->{op.technique}->{target_id}"
        if edge_id in edge_ids:
            continue
        edges.append(
            {
                "id": edge_id,
                "source": source_id,
                "target": target_id,
                "type": op.technique,
                "severity": op.severity,
                "mitre_id": op.mitre_id,
            }
        )
        edge_ids.add(edge_id)

    graph["nodes"] = nodes
    graph["edges"] = edges
    graph_store.save(graph)


@dataclass
class KerberosAnalysisResult:
    opportunities: list[KerberosOpportunity] = field(default_factory=list)
    output_path: str | None = None
    graph_path: str | None = None


def run_kerberos_analysis(session: Session) -> KerberosAnalysisResult:
    """Phase 11 — Kerberos attack surface from inventory, delegations, and ACLs."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before kerberos")

    ws_name = session.workspace.name
    ws_path = session.workspaces.path_for(ws_name)
    owned = _owned_set(session)

    print_info("Phase 11 — advanced Kerberos analysis")

    inventory = _load_json(ws_path / "auth_inventory.json")
    if inventory is None:
        raise ValueError("no auth_inventory.json — run start_auth first")

    acl_data = _load_json(ws_path / "acl_findings.json")
    acl_findings = list((acl_data or {}).get("findings") or [])

    opportunities: list[KerberosOpportunity] = []
    opportunities.extend(_from_delegations(inventory.get("delegations") or [], owned))
    opportunities.extend(_from_acl_findings(acl_findings, owned))
    opportunities.extend(_from_backup_operators(inventory.get("groups") or [], owned))
    opportunities.extend(_from_computers(inventory.get("computers") or []))

    # Deduplicate by technique + source + target
    seen: set[tuple[str, str, str | None]] = set()
    unique: list[KerberosOpportunity] = []
    for op in opportunities:
        key = (op.technique, op.source_object.lower(), op.target)
        if key in seen:
            continue
        seen.add(key)
        unique.append(op)

    for idx, op in enumerate(unique, start=1):
        op.id = f"krb-{idx:03d}"

    result = KerberosAnalysisResult(opportunities=unique)
    out_path = ws_path / "kerberos_ops.json"
    payload = {
        "domain": domain,
        "owned_users": list(session.workspace.owned_users),
        "opportunity_count": len(unique),
        "owned_relevant_count": sum(1 for o in unique if o.owned_relevant),
        "opportunities": [o.to_dict() for o in unique],
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result.output_path = str(out_path)

    owned_ops = [o for o in unique if o.owned_relevant]
    if owned_ops:
        graph_store = GraphStore(session.workspaces, ws_name)
        _enrich_graph(graph_store, domain, owned_ops)
        result.graph_path = str(graph_store.path)
        print_success("graph updated with Kerberos edges → graph.json")

    if unique:
        rows = [
            [
                o.id,
                o.technique,
                o.source_object,
                o.target or "",
                "yes" if o.owned_relevant else "",
                o.severity,
            ]
            for o in unique[:20]
        ]
        print_table(
            "Kerberos opportunities",
            ["id", "technique", "source", "target", "owned", "severity"],
            rows,
        )
    else:
        print_warning("no Kerberos opportunities — enrich inventory with start_auth / acls")

    print_success("Kerberos analysis saved → kerberos_ops.json")
    print_manual_guide("kerberos_adv", session=session)
    return result


def get_kerberos_op(session: Session, op_id: str) -> dict[str, Any] | None:
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    path = session.workspaces.path_for(session.workspace.name) / "kerberos_ops.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data.get("opportunities", []):
        if str(item.get("id")) == op_id:
            return item
    return None
