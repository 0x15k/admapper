from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from admapper.models.escalation import EscalationEdge
from admapper.wsus.prerequisites import owned_groups_for_user

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Prefer direct/simple hops; WSUS+AD CS chain is the preferred DA path when chain is available
_TECHNIQUE_RANK = {
    "forcechangepassword": 10,
    "genericall": 9,
    "genericwrite": 8,
    "readgmsapassword": 8,
    "dcsync": 10,
    "addmember": 9,
    "wsus_cert_chain": 10,
    "wsus_spoof": 9,
    "esc1": 8,
    "esc9": 8,
    "esc10": 8,
    "esc11": 7,
    "esc13": 7,
    "esc14": 6,
    "template_enrollment": 5,
    "esc4": 7,
    "dll_hijack_scheduled_task": 10,
    "adminto": 5,
    "rbcd": 9,
    "constrained_delegation": 9,
    "shadow_credentials": 9,
    "golden_ticket": 10,
    "silver_ticket": 7,
    "laps_read": 8,
    "gpo_abuse": 8,
    "overpass_the_hash": 7,
    "trust_ticket": 8,
}


def _load(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _owned_set(owned: list[str]) -> set[str]:
    return {u.lower() for u in owned}


def _is_owned(name: str, owned: set[str]) -> bool:
    if not name:
        return False
    lower = name.lower()
    if lower in owned:
        return True
    # gMSA / machine helpers: machine name with or without trailing $
    # example: msa_target vs msa_target$
    if lower.endswith("$"):
        return lower.rstrip("$") in owned
    return f"{lower}$" in owned


def _extract_run_as(detail: str) -> str:
    m = re.search(r"runs as ([^|]+)", detail, re.I)
    return m.group(1).strip() if m else ""


def collect_edges_from_pivot(
    *,
    pivot_user: str,
    owned_users: list[str],
    ws_path: Path,
    domain: str = "",
) -> list[EscalationEdge]:
    """Collect 1-hop escalation options outbound from pivot_user (BloodHound-style)."""
    owned = _owned_set(owned_users)
    pivot_l = pivot_user.lower()
    edges: list[EscalationEdge] = []

    inventory = _load(ws_path / "auth_inventory.json") or {}
    groups = owned_groups_for_user(inventory, pivot_user)

    # ── Group membership → capabilities (no extra hop) ──
    for group in groups:
        edges.append(
            EscalationEdge(
                technique="member_of",
                module="graph",
                title=f"Member of {group}",
                severity="info",
                summary=f"{pivot_user} ∈ {group} — check outbound abuse for this group",
                target=group,
                ready=True,
                mitre_id="T1078",
            )
        )

    # ── ACL findings (principal == pivot) ──
    acl_data = _load(ws_path / "acl_findings.json") or {}
    for finding in acl_data.get("findings") or []:
        if str(finding.get("principal", "")).lower() != pivot_l:
            continue
        target = str(finding.get("target_name") or finding.get("target_dn") or "")
        right = str(finding.get("right") or "")

        if finding.get("target_type") == "gpo":
            gpo_dn = str(finding.get("target_dn") or "")
            m = re.search(r"({[a-fA-F0-9-]+})", gpo_dn, re.I)
            gpo_guid = m.group(1) if m else target

            affected_ou_dns = []
            for ou in inventory.get("ous", []):
                ou_gplink = str(ou.get("gplink") or "")
                if gpo_guid.lower() in ou_gplink.lower():
                    affected_ou_dns.append(str(ou.get("dn") or "").lower())

            domain_gplink = str(inventory.get("domain_gplink") or "")
            link_to_domain = gpo_guid.lower() in domain_gplink.lower()

            affected_computers = []
            for comp in inventory.get("computers", []):
                comp_dn = str(comp.get("dn") or "").lower()
                comp_name = str(comp.get("name") or "")
                is_affected = link_to_domain
                if not is_affected:
                    for ou_dn in affected_ou_dns:
                        if comp_dn.endswith(ou_dn):
                            is_affected = True
                            break
                if is_affected:
                    affected_computers.append(comp_name)

            for comp in affected_computers:
                comp_owned = _is_owned(comp, owned)
                edges.append(
                    EscalationEdge(
                        technique="gpo_abuse",
                        module="acls",
                        title=f"gpo_abuse → {comp}",
                        severity=str(finding.get("severity") or "high"),
                        summary=f"Pivot has write access to GPO linked to {comp}. Inject task to execute commands as SYSTEM.",
                        target=comp,
                        op_id=str(finding.get("id") or ""),
                        ready=not comp_owned,
                        target_owned=comp_owned,
                        manual_commands=list(finding.get("manual_commands") or []),
                        mitre_id="T1484.001",
                    )
                )
            if not affected_computers:
                target_owned = _is_owned(target, owned)
                edges.append(
                    EscalationEdge(
                        technique="gpo_abuse",
                        module="acls",
                        title=f"gpo_abuse → {target}",
                        severity=str(finding.get("severity") or "high"),
                        summary=f"Pivot has write access to GPO {target}.",
                        target=target,
                        op_id=str(finding.get("id") or ""),
                        ready=not target_owned,
                        target_owned=target_owned,
                        manual_commands=list(finding.get("manual_commands") or []),
                        mitre_id="T1484.001",
                    )
                )
            continue

        target_owned = _is_owned(target, owned)
        edges.append(
            EscalationEdge(
                technique=right,
                module="acls",
                title=f"{right} → {target}",
                severity=str(finding.get("severity") or "medium"),
                summary=str(finding.get("summary") or ""),
                target=target,
                op_id=str(finding.get("id") or ""),
                ready=not target_owned,
                target_owned=target_owned,
                manual_commands=list(finding.get("manual_commands") or []),
                mitre_id=str(finding.get("mitre_id") or "T1098"),
            )
        )

    # ── Post-ex (pivot has shell / deploys as context) ──
    postex = _load(ws_path / "postex_ops.json") or {}
    for op in postex.get("opportunities") or []:
        ctx = str(op.get("context") or "").lower()
        technique = str(op.get("technique") or "")
        if ctx != pivot_l and technique != "dll_hijack_scheduled_task":
            continue
        if technique == "dll_hijack_scheduled_task":
            target = _extract_run_as(str(op.get("detail") or ""))
            if not target:
                scan = _load(ws_path / "postex_scan.json") or {}
                findings = scan.get("findings") or []
                if findings:
                    target = str(findings[0].get("run_as_user") or "")
        else:
            target = str(op.get("target_host") or "")
        target_owned = _is_owned(target, owned)
        edges.append(
            EscalationEdge(
                technique=technique,
                module="postex",
                title=str(op.get("title") or technique),
                severity=str(op.get("severity") or "medium"),
                summary=str(op.get("detail") or op.get("summary") or "")[:200],
                target=target,
                op_id=str(op.get("id") or ""),
                ready=not target_owned and technique == "dll_hijack_scheduled_task",
                target_owned=target_owned,
                manual_commands=list(op.get("manual_commands") or []),
                mitre_id=str(op.get("mitre_id") or ""),
            )
        )

    # ── AD CS (principal == pivot) ──
    adcs = _load(ws_path / "adcs_findings.json") or {}
    for finding in adcs.get("findings") or []:
        principal = str(finding.get("principal") or "").lower()
        if principal and principal != pivot_l:
            continue
        if not principal and finding.get("esc") == "golden_cert":
            continue
        esc = str(finding.get("esc") or "")
        template = str(finding.get("template") or "")
        # Server-Auth-only templates (e.g. <template>) feed WSUS — not a standalone NEXT hop
        if esc == "template_enrollment" and finding.get("wsus_chain_step"):
            continue
        if (
            esc == "template_enrollment"
            and "group membership suggests"
            in str(finding.get("detail") or finding.get("summary") or "").lower()
        ):
            continue
        edges.append(
            EscalationEdge(
                technique=esc,
                module="adcs",
                title=str(finding.get("title") or esc),
                severity=str(finding.get("severity") or "high"),
                summary=str(finding.get("detail") or finding.get("summary") or ""),
                target=template or str(finding.get("ca_name") or ""),
                op_id=str(finding.get("id") or ""),
                ready=bool(finding.get("prerequisites_met", True)),
                manual_commands=list(finding.get("manual_commands") or []),
                mitre_id=str(finding.get("mitre_id") or "T1649"),
            )
        )

    # ── Kerberos opportunities ──
    krb = _load(ws_path / "kerberos_ops.json") or {}
    for op in krb.get("opportunities") or []:
        if str(op.get("context") or "").lower() not in {pivot_l, ""}:
            continue
        if not op.get("owned_relevant", True):
            continue
        edges.append(
            EscalationEdge(
                technique=str(op.get("technique") or ""),
                module="kerberos",
                title=str(op.get("title") or ""),
                severity=str(op.get("severity") or "medium"),
                summary=str(op.get("summary") or ""),
                target=str(op.get("target_host") or op.get("target") or ""),
                op_id=str(op.get("id") or ""),
                manual_commands=list(op.get("manual_commands") or []),
                mitre_id=str(op.get("mitre_id") or ""),
            )
        )

    # ── WSUS (context == pivot) — primary DA path when AD CS + IT enrollment ──
    wsus = _load(ws_path / "wsus_ops.json") or {}
    for op in wsus.get("opportunities") or []:
        if str(op.get("context") or "").lower() != pivot_l:
            continue
        technique = str(op.get("technique") or "")
        if technique == "wsus_admin_enum":
            continue
        edges.append(
            EscalationEdge(
                technique=technique,
                module="wsus",
                title=str(op.get("title") or technique),
                severity=str(op.get("severity") or "medium"),
                summary=str(op.get("detail") or op.get("summary") or ""),
                target=str(op.get("target_host") or ""),
                op_id=str(op.get("id") or ""),
                ready=bool(op.get("prerequisites_met", False)),
                manual_commands=list(op.get("manual_commands") or []),
                mitre_id=str(op.get("mitre_id") or "T1195.002"),
            )
        )

    # ── Graph: first hop on shortest path from pivot ──
    graph = _load(ws_path / "graph.json") or {}
    paths = _load(ws_path / "paths.json") or {}
    pivot_node = f"user:{pivot_l}@{domain.lower()}" if domain else ""
    for path in paths.get("paths") or []:
        if pivot_node and str(path.get("source")) != pivot_node:
            continue
        steps = path.get("steps") or []
        if not steps:
            continue
        step = steps[0]
        tgt_label = str(path.get("target_label") or path.get("target") or "")
        edges.append(
            EscalationEdge(
                technique=str(step.get("edge_type") or "path"),
                module="paths",
                title=f"Path hop → {tgt_label}",
                severity=str(path.get("impact") or "high"),
                summary=str(step.get("narrative") or ""),
                target=tgt_label,
                op_id=str(path.get("id") or ""),
                manual_commands=[f"paths show {path.get('id')}"],
                mitre_id=str(step.get("mitre_id") or ""),
            )
        )

    # ── Trust relationships ──
    trust_data = _load(ws_path / "trust_info.json") or {}
    for trust in trust_data.get("trusts") or []:
        partner = str(trust.get("partner") or "")
        direction = str(trust.get("direction") or "")
        sid_filter = trust.get("sid_filtering", True)
        if direction in ("Outbound", "Bidirectional") and partner:
            severity = "critical" if not sid_filter else "high"
            edges.append(
                EscalationEdge(
                    technique="trust_ticket",
                    module="trusts",
                    title=f"Trust → {partner} ({direction})",
                    severity=severity,
                    summary=f"{'SID filtering OFF — ' if not sid_filter else ''}"
                    f"trust ticket forging + cross-domain escalation",
                    target=partner,
                    ready=True,
                    manual_commands=[
                        "# Forge inter-realm TGT with trust key",
                        f"ticketer.py -nthash <trust_hash> -domain-sid <SID> "
                        f"-domain {domain} -spn krbtgt/{partner} administrator",
                    ],
                    mitre_id="T1134.005",
                )
            )

    # ── LAPS readable computers ──
    laps_data = _load(ws_path / "laps_credentials.json") or {}
    for laps_cred in laps_data.get("credentials") or []:
        computer = str(laps_cred.get("computer") or "")
        if computer:
            edges.append(
                EscalationEdge(
                    technique="laps_read",
                    module="laps",
                    title=f"LAPS → {computer}",
                    severity="high",
                    summary=f"Local admin password readable for {computer}",
                    target=computer,
                    ready=True,
                    mitre_id="T1552.004",
                )
            )

    # ── Delegation opportunities (RBCD / constrained) ──
    for finding in acl_data.get("findings") or []:
        right = str(finding.get("right") or "").lower()
        target = str(finding.get("target_name") or "")
        principal = str(finding.get("principal") or "").lower()
        if principal != pivot_l:
            continue
        # GenericWrite on computer → RBCD candidate
        if right in ("genericwrite", "genericall", "writedacl") and target.endswith("$"):
            edges.append(
                EscalationEdge(
                    technique="rbcd",
                    module="delegation",
                    title=f"RBCD → {target}",
                    severity="critical",
                    summary=f"{right} on {target} — configure RBCD for S4U2Proxy impersonation",
                    target=target,
                    ready=True,
                    manual_commands=[
                        f"addcomputer.py -computer-name ADMAPPER$ -dc-ip <DC> {domain}/user:pass",
                        f"rbcd.py -delegate-from ADMAPPER$ -delegate-to {target} -action write ...",
                        f"getST.py -spn cifs/{target} -impersonate administrator ...",
                    ],
                    mitre_id="T1134.001",
                )
            )
        # GenericWrite on user → Shadow Credentials candidate
        if right in ("genericwrite", "genericall") and not target.endswith("$"):
            edges.append(
                EscalationEdge(
                    technique="shadow_credentials",
                    module="shadow_creds",
                    title=f"Shadow Creds → {target}",
                    severity="high",
                    summary=f"{right} on {target} — inject key credential for PKINIT auth",
                    target=target,
                    ready=True,
                    manual_commands=[
                        f"pywhisker -d {domain} -u <user> --target {target} -a add",
                        "certipy auth -pfx <target>.pfx -dc-ip <DC>",
                    ],
                    mitre_id="T1556.006",
                )
            )

    # Dedupe by technique+target+module
    seen: set[tuple[str, str, str]] = set()
    unique: list[EscalationEdge] = []
    for edge in edges:
        key = (edge.module, edge.technique, edge.target.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(edge)

    return sort_edges(unique)


def sort_edges(edges: list[EscalationEdge]) -> list[EscalationEdge]:
    def key(edge: EscalationEdge) -> tuple[int, int, int, int, str]:
        owned_penalty = 1 if edge.target_owned else 0
        ready_bonus = 0 if edge.ready else 1
        sev = _SEVERITY_RANK.get(edge.severity.lower(), 0)
        tech = _TECHNIQUE_RANK.get(edge.technique.lower(), 1)
        return (-owned_penalty, ready_bonus, -tech, -sev, edge.title)

    return sorted(edges, key=key)


def pick_next_edge(edges: list[EscalationEdge]) -> EscalationEdge | None:
    """Best next hop: ready, target not owned, highest severity, simplest technique."""
    for edge in sort_edges(edges):
        if edge.ready and not edge.target_owned and edge.technique != "member_of":
            return edge
    for edge in sort_edges(edges):
        if edge.ready and not edge.target_owned:
            return edge
    return None
