from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from admapper.coerce.catalog import coerce_meta
from admapper.core.hosts import HostsStore
from admapper.core.json_io import load_json
from admapper.core.output import print_info, print_success, print_table, print_warning
from admapper.guides.render import print_manual_guide
from admapper.models.coerce_op import CoerceOpportunity

if TYPE_CHECKING:
    from admapper.core.session import Session


def _load_json(path) -> dict[str, Any] | None:
    return load_json(path)


def _opportunity(
    technique: str,
    *,
    source_host: str | None = None,
    listener_host: str | None = None,
    relay_target: str | None = None,
    detail: str = "",
) -> CoerceOpportunity:
    meta = coerce_meta(technique)
    return CoerceOpportunity(
        technique=technique,
        title=meta.title,
        severity=meta.severity,
        mitre_id=meta.mitre_id,
        summary=meta.summary,
        source_host=source_host,
        listener_host=listener_host,
        relay_target=relay_target,
        detail=detail,
        manual_commands=list(meta.manual_commands),
    )


def _dc_hosts(session: Session) -> list[str]:
    if session.workspace is None:
        return []
    hosts = HostsStore(session.workspaces, session.workspace.name).list()
    return [
        h.address
        for h in hosts
        if h.is_domain_controller and h.address
    ]


def _unconstrained_listeners(inventory: dict[str, Any]) -> list[str]:
    listeners: list[str] = []
    for item in inventory.get("delegations") or []:
        if str(item.get("delegation_type")) != "unconstrained":
            continue
        name = str(item.get("object_name", ""))
        if name:
            listeners.append(name.rstrip("$"))
    for computer in inventory.get("computers") or []:
        if computer.get("unconstrained_delegation"):
            name = str(computer.get("name", ""))
            if name and name not in listeners:
                listeners.append(name)
    return listeners


def _coercion_targets(
    *,
    dcs: list[str],
    computers: list[dict[str, Any]],
) -> list[str]:
    targets: list[str] = []
    targets.extend(dcs)
    for computer in computers:
        name = str(computer.get("name", ""))
        dns = str(computer.get("dns_host") or "")
        if name and name not in targets:
            targets.append(dns or name)
    return targets[:30]


def build_coerce_opportunities(
    session: Session,
    *,
    inventory: dict[str, Any] | None,
    adcs_data: dict[str, Any] | None,
    kerberos_data: dict[str, Any] | None,
    acl_data: dict[str, Any] | None,
) -> list[CoerceOpportunity]:
    """Phase 13 — derive coercion and relay playbooks from workspace intel."""
    ops: list[CoerceOpportunity] = []
    dcs = _dc_hosts(session)
    inv = inventory or {}
    computers = list(inv.get("computers") or [])
    listeners = _unconstrained_listeners(inv)
    coerce_targets = _coercion_targets(dcs=dcs, computers=computers)
    smb_signing = inv.get("smb_signing_required")
    default_listener = listeners[0] if listeners else "<attacker_ip>"

    primary_targets = dcs or coerce_targets[:3]
    for target in primary_targets:
        for method in ("petitpotam", "printerbug"):
            ops.append(
                _opportunity(
                    method,
                    source_host=target,
                    listener_host=default_listener,
                    detail=(
                        f"Coerce {target} → listener {default_listener}"
                        + (" (unconstrained capture)" if listeners else "")
                    ),
                )
            )
    if primary_targets:
        first = primary_targets[0]
        for method in ("dfscoerce", "mseven", "shadowcoerce"):
            ops.append(
                _opportunity(
                    method,
                    source_host=first,
                    listener_host=default_listener,
                    detail=f"Alternate RPC coercion against {first}",
                )
            )

    # Relay → LDAP when signing may allow relay + RBCD/shadow paths exist
    krb_ops = list((kerberos_data or {}).get("opportunities") or [])
    acl_findings = list((acl_data or {}).get("findings") or [])
    has_rbcd_path = any(
        o.get("technique") in {"rbcd", "shadow_credentials"} for o in krb_ops
    ) or any(
        o.get("right") in {"genericwrite", "genericall"}
        and o.get("target_type") == "computer"
        for o in acl_findings
    )
    relay_viable = smb_signing is False or smb_signing is None
    dc_target = dcs[0] if dcs else "<DC>"
    if relay_viable or has_rbcd_path:
        ops.append(
            _opportunity(
                "relay_ldap",
                source_host=dc_target,
                relay_target=f"ldap://{dc_target}",
                detail=(
                    "SMB signing not enforced"
                    if smb_signing is False
                    else "LDAP relay for RBCD/shadow creds"
                ),
            )
        )
        if smb_signing is False:
            ops.append(
                _opportunity(
                    "relay_ntlmv1",
                    source_host=dc_target,
                    relay_target=f"ldap://{dc_target}",
                    detail="SMB signing disabled — watch for NTLMv1 downgrade",
                )
            )

    # Relay → ADCS from ESC8 findings
    adcs_findings = list((adcs_data or {}).get("findings") or [])
    for finding in adcs_findings:
        if str(finding.get("esc")) != "esc8":
            continue
        ca = str(finding.get("ca_name") or "")
        inv_services = list((adcs_data or {}).get("enrollment_services") or [])
        dns_host = ca
        for svc in inv_services:
            if str(svc.get("name")) == ca:
                dns_host = str(svc.get("dns_host") or ca)
                break
        relay_url = f"http://{dns_host}/certsrv/certfnsh.asp"
        ops.append(
            _opportunity(
                "relay_adcs",
                source_host=dcs[0] if dcs else dns_host,
                listener_host=default_listener,
                relay_target=relay_url,
                detail=f"ESC8 web enrollment @ {dns_host}",
            )
        )

    # Deduplicate
    seen: set[tuple[str, str | None, str | None]] = set()
    unique: list[CoerceOpportunity] = []
    for op in ops:
        key = (op.technique, op.source_host, op.relay_target)
        if key in seen:
            continue
        seen.add(key)
        unique.append(op)
    return unique


@dataclass
class CoerceAnalysisResult:
    opportunities: list[CoerceOpportunity] = field(default_factory=list)
    output_path: str | None = None


def run_coerce_analysis(session: Session) -> CoerceAnalysisResult:
    """Phase 13 — coercion + NTLM relay playbook from workspace artefacts."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before coerce")

    ws_name = session.workspace.name
    ws_path = session.workspaces.path_for(ws_name)

    print_info("Phase 13 — coercion & relay analysis")

    inventory = _load_json(ws_path / "auth_inventory.json")
    if inventory is None:
        print_warning("no auth_inventory.json — run start_auth for richer coerce targets")

    adcs_inv = _load_json(ws_path / "adcs_inventory.json")
    adcs_findings = _load_json(ws_path / "adcs_findings.json")
    adcs_payload: dict[str, Any] | None = None
    if adcs_findings or adcs_inv:
        adcs_payload = {
            "findings": (adcs_findings or {}).get("findings", []),
            "enrollment_services": (adcs_inv or {}).get("enrollment_services", []),
        }

    opportunities = build_coerce_opportunities(
        session,
        inventory=inventory,
        adcs_data=adcs_payload,
        kerberos_data=_load_json(ws_path / "kerberos_ops.json"),
        acl_data=_load_json(ws_path / "acl_findings.json"),
    )
    for idx, op in enumerate(opportunities, start=1):
        op.id = f"coerce-{idx:03d}"

    result = CoerceAnalysisResult(opportunities=opportunities)
    out_path = ws_path / "coerce_ops.json"
    out_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "opportunity_count": len(opportunities),
                "unconstrained_listeners": _unconstrained_listeners(inventory or {}),
                "domain_controllers": _dc_hosts(session),
                "opportunities": [o.to_dict() for o in opportunities],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    result.output_path = str(out_path)

    if opportunities:
        rows = [
            [
                o.id,
                o.technique,
                o.source_host or "",
                o.listener_host or "",
                o.relay_target or "",
            ]
            for o in opportunities[:20]
        ]
        print_table(
            "Coercion / relay opportunities",
            ["id", "technique", "source", "listener", "relay"],
            rows,
        )
    else:
        print_warning("no coercion paths — run start_auth and adcs first")

    print_success("coercion playbook saved → coerce_ops.json")
    print_manual_guide("coercion", session=session)
    return result


def get_coerce_op(session: Session, op_id: str) -> dict[str, Any] | None:
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    path = session.workspaces.path_for(session.workspace.name) / "coerce_ops.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data.get("opportunities", []):
        if str(item.get("id")) == op_id:
            return item
    return None
