from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from admapper.creds.common import pick_dc_ip
from admapper.guides.render import print_manual_guide
from admapper.models.chain_op import ChainOpportunity, ChainStep
from admapper.support.output import print_info, print_success, print_table, print_warning

if TYPE_CHECKING:
    from admapper.support.session import Session


def _load_json(path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _owned_users(session: Session) -> list[str]:
    if session.workspace is None:
        return []
    return list(session.workspace.owned_users)


def _find_op(ops: list[dict], technique: str, *, context: str | None = None) -> dict | None:
    for op in ops:
        if str(op.get("technique")) != technique:
            continue
        if context and str(op.get("context", "")).lower() != context.lower():
            continue
        return op
    return None


def build_attack_chains(
    session: Session,
    *,
    postex_ops: dict[str, Any] | None,
    adcs_findings: dict[str, Any] | None,
    wsus_ops: dict[str, Any] | None,
    postex_scan: dict[str, Any] | None,
    inventory: dict[str, Any] | None,
    dc_ip: str | None,
) -> list[ChainOpportunity]:
    """Build multi-step attack chains with per-step readiness."""
    chains: list[ChainOpportunity] = []
    owned = _owned_users(session)
    target = dc_ip or pick_dc_ip(session) or "<DC>"

    postex_list = (postex_ops or {}).get("opportunities") or []
    adcs_list = (adcs_findings or {}).get("findings") or []
    wsus_list = (wsus_ops or {}).get("opportunities") or []

    # Chain: DLL hijack → AD CS template → WSUS → DA
    hijack_ops = [o for o in postex_list if o.get("technique") == "dll_hijack_scheduled_task"]
    for hijack in hijack_ops:
        pivot_user = str(hijack.get("detail", "")).split("runs as ")
        pivot = pivot_user[1].split("|")[0].strip() if len(pivot_user) > 1 else ""
        if not pivot:
            scan_findings = (postex_scan or {}).get("findings") or []
            if scan_findings:
                pivot = str(scan_findings[0].get("run_as_user") or "")

        hijack_ready = pivot.lower() in {u.lower() for u in owned}
        hijack_id = str(hijack.get("id") or "")

        enroll = next(
            (
                f
                for f in adcs_list
                if str(f.get("esc")) in ("template_enrollment", "esc4")
                and str(f.get("principal", "")).lower() == pivot.lower()
            ),
            None,
        )
        enroll_ready = enroll is not None and pivot.lower() in {u.lower() for u in owned}
        enroll_id = str(enroll.get("id", "")) if enroll else None
        template = str(enroll.get("template") or "") if enroll else ""

        wsus_op = _find_op(wsus_list, "wsus_cert_chain", context=pivot) or _find_op(
            wsus_list, "wsus_spoof", context=pivot
        )
        wsus_ready = bool(wsus_op and wsus_op.get("prerequisites_met"))
        wsus_id = str(wsus_op.get("id", "")) if wsus_op else None

        steps = [
            ChainStep(
                order=1,
                technique="dll_hijack_scheduled_task",
                module="postex",
                op_id=hijack_id or None,
                title="Scheduled task DLL hijack",
                ready=hijack_ready,
                detail=f"Pivot to {pivot}" if pivot else hijack.get("summary", ""),
            ),
            ChainStep(
                order=2,
                technique="template_enrollment",
                module="adcs",
                op_id=enroll_id,
                title=f"AD CS template abuse ({template})" if template else "AD CS template abuse",
                ready=enroll_ready,
                detail=f"Enroll {template} as {pivot}"
                if template
                else "Run adcs after owning pivot user",
            ),
            ChainStep(
                order=3,
                technique="wsus_cert_chain",
                module="wsus",
                op_id=wsus_id,
                title="WSUS spoof / cert chain to DA",
                ready=wsus_ready,
                detail="WSUS + machine cert authentication toward Domain Admin",
            ),
        ]

        next_step = next((s for s in steps if not s.ready), None)
        commands: list[str] = []
        if not hijack_ready and hijack_id:
            commands.append(f"admapper postex run --op {hijack_id} -w <workspace>")
        elif hijack_ready and not enroll_ready:
            commands.append(f"admapper adcs -w <workspace>  # re-run as {pivot}")
            commands.append(
                "certipy find -u <user>@<domain> -hashes :<NTLM> -dc-ip <DC> -vulnerable"
            )
        elif enroll_ready and not wsus_ready:
            commands.append("admapper wsus -w <workspace>")
            if template:
                commands.append(
                    f"certipy req -u {pivot}@<domain> -hashes :<NTLM> -ca <CA> "
                    f"-template {template} -dns <dc_fqdn>"
                )
        elif wsus_ready and wsus_id:
            commands.append(f"admapper wsus show {wsus_id} -w <workspace>")

        chain_ready = wsus_ready
        chains.append(
            ChainOpportunity(
                chain_id="dll_hijack_adcs_wsus_da",
                title="DLL hijack → AD CS → WSUS → DA",
                severity="critical",
                summary="Lateral via scheduled task, enroll restricted cert template, abuse WSUS toward DA",
                target_host=target,
                context=pivot or None,
                steps=steps,
                ready=chain_ready,
                manual_commands=commands,
            )
        )

    # Chain: owned user with direct AD CS ESC (no hijack required)
    for finding in adcs_list:
        esc = str(finding.get("esc") or "")
        principal = str(finding.get("principal") or "")
        if esc not in ("esc1", "esc4", "template_enrollment") or not principal:
            continue
        if principal.lower() not in {u.lower() for u in owned}:
            continue
        if any(c.context == principal for c in chains):
            continue
        steps = [
            ChainStep(
                order=1,
                technique=esc,
                module="adcs",
                op_id=str(finding.get("id") or ""),
                title=str(finding.get("title") or esc),
                ready=True,
                detail=str(finding.get("detail") or ""),
            ),
        ]
        chains.append(
            ChainOpportunity(
                chain_id=f"adcs_{esc}",
                title=f"AD CS {esc.upper()} as {principal}",
                severity=str(finding.get("severity") or "high"),
                summary=str(finding.get("summary") or ""),
                target_host=target,
                context=principal,
                steps=steps,
                ready=True,
                manual_commands=list(finding.get("manual_commands") or []),
            )
        )

    # 1. Unconstrained Delegation + Print Spooler Coercion -> Domain Compromise
    from admapper.stores.findings import FindingsStore
    ws_name = session.workspace.name if session.workspace else None
    findings = []
    if ws_name:
        try:
            findings = FindingsStore(session.workspaces, ws_name).list()
        except Exception:
            pass

    unconstrained_hosts: list[str] = []
    for f in findings:
        if f.key.startswith("unconstrained_delegation_"):
            name = (
                f.title.split(" on ")[-1].strip()
                if " on " in f.title
                else f.key.replace("unconstrained_delegation_", "")
            )
            if name and name.lower() not in (h.lower() for h in unconstrained_hosts):
                unconstrained_hosts.append(name)

    if inventory:
        for item in inventory.get("delegations") or []:
            if str(item.get("delegation_type")).lower() == "unconstrained":
                name = str(item.get("object_name", "")).rstrip("$")
                if name and name.lower() not in (h.lower() for h in unconstrained_hosts):
                    unconstrained_hosts.append(name)
        for computer in inventory.get("computers") or []:
            if computer.get("unconstrained_delegation"):
                name = str(computer.get("name", "")).rstrip("$")
                if name and name.lower() not in (h.lower() for h in unconstrained_hosts):
                    unconstrained_hosts.append(name)

    has_spooler_coercion = False
    for f in findings:
        f_key_lower = f.key.lower()
        f_title_lower = f.title.lower()
        if (
            "printerbug" in f_key_lower
            or "printnightmare" in f_key_lower
            or "spooler" in f_title_lower
        ):
            has_spooler_coercion = True
            break

    if ws_name and not has_spooler_coercion:
        try:
            c_path = session.workspaces.path_for(ws_name) / "coerce_ops.json"
            if c_path.is_file():
                c_data = json.loads(c_path.read_text(encoding="utf-8"))
                for op in c_data.get("opportunities", []):
                    op_tech = str(op.get("technique", "")).lower()
                    op_detail = str(op.get("detail", "")).lower()
                    if op_tech in ("printerbug", "printnightmare") or "spooler" in op_detail:
                        has_spooler_coercion = True
                        break
        except Exception:
            pass

    if unconstrained_hosts and has_spooler_coercion:
        target_dc = target
        host_name = unconstrained_hosts[0]
        c_steps = [
            ChainStep(
                order=1,
                technique="printerbug",
                module="coerce",
                op_id=None,
                title="DC Spooler Coercion",
                ready=True,
                detail=f"Force DC {target_dc} to authenticate to {host_name}",
            ),
            ChainStep(
                order=2,
                technique="tgt_harvest",
                module="kerberos",
                op_id=None,
                title="TGT Harvest",
                ready=False,
                detail=f"Harvest DC TGT from memory on unconstrained delegation host {host_name}",
            ),
        ]
        cmd_coerce = f"printerbug.py <domain>/<user>:<password>@{target_dc} {host_name}"
        cmd_harvest = f"admapper kerberos roast --host {host_name}"
        chains.append(
            ChainOpportunity(
                chain_id="coercion_tgt_harvest_dc",
                title="Coercion → TGT Harvest → Domain Compromise",
                severity="critical",
                summary=(
                    f"Abuse Print Spooler on DC to coerce authentication to unconstrained "
                    f"delegation host {host_name}, harvesting the DC TGT for domain compromise"
                ),
                target_host=target_dc,
                context=host_name,
                steps=c_steps,
                ready=False,
                manual_commands=[cmd_coerce, cmd_harvest],
            )
        )

    # 2. ACL Abuse + Kerberoast -> Credential Access
    kerberoastable_users = set()
    if inventory:
        for u in inventory.get("users") or []:
            uname = str(u.get("username", "")).lower()
            if u.get("kerberoastable") and uname != "krbtgt":
                kerberoastable_users.add(uname)

    if ws_name:
        try:
            users_json_path = session.workspaces.path_for(ws_name) / "users.json"
            if users_json_path.is_file():
                u_data = json.loads(users_json_path.read_text(encoding="utf-8"))
                raw_users = u_data.get("users", []) if isinstance(u_data, dict) else u_data
                if isinstance(raw_users, list):
                    for u in raw_users:
                        uname = str(u.get("username", "")).lower()
                        if u.get("kerberoastable") and uname != "krbtgt":
                            kerberoastable_users.add(uname)
        except Exception:
            pass

    acl_findings = []
    if ws_name:
        try:
            acl_path = session.workspaces.path_for(ws_name) / "acl_findings.json"
            if acl_path.is_file():
                acl_data = json.loads(acl_path.read_text(encoding="utf-8"))
                acl_findings = acl_data.get("findings", [])
        except Exception:
            pass

    seen_roast_targets = set()
    for acl in acl_findings:
        target_type = str(acl.get("target_type", "")).lower()
        right = str(acl.get("right", "")).lower()
        target_name = str(acl.get("target_name", "")).lower()
        principal = str(acl.get("principal", "")).lower()

        if (
            target_type == "user"
            and right in ("genericwrite", "genericall")
            and target_name in kerberoastable_users
        ):
            if target_name in seen_roast_targets:
                continue
            seen_roast_targets.add(target_name)

            principal_owned = principal in (u.lower() for u in owned)
            acl_id = str(acl.get("id", ""))
            target_user_display = acl.get("target_name")
            principal_display = acl.get("principal")
            right_display = acl.get("right")

            steps = [
                ChainStep(
                    order=1,
                    technique=right,
                    module="acl",
                    op_id=acl_id or None,
                    title=f"Write SPN to {target_user_display}",
                    ready=principal_owned,
                    detail=(
                        f"Use {principal_display}'s {right_display} right to add an SPN "
                        f"to {target_user_display}"
                    ),
                ),
                ChainStep(
                    order=2,
                    technique="kerberoast",
                    module="kerberos",
                    op_id=None,
                    title=f"Kerberoast {target_user_display}",
                    ready=principal_owned,
                    detail=f"Request a TGS ticket for {target_user_display} and crack offline",
                ),
            ]
            cmd_acl = (
                f"admapper acl run --finding {acl_id} -w <workspace>"
                if acl_id
                else "admapper acl run -w <workspace>"
            )
            cmd_roast = "admapper kerberos roast -w <workspace>"

            chains.append(
                ChainOpportunity(
                    chain_id="acl_abuse_kerberoast",
                    title="ACL Abuse → Kerberoast → Credential Access",
                    severity="critical",
                    summary=(
                        f"Abuse {right_display} on kerberoastable user {target_user_display} "
                        f"to add SPN, then Kerberoast the account to crack credentials"
                    ),
                    target_host=target,
                    context=target_user_display,
                    steps=steps,
                    ready=principal_owned,
                    manual_commands=[cmd_acl, cmd_roast],
                )
            )

    return chains


@dataclass
class ChainAnalysisResult:
    chains: list[ChainOpportunity] = field(default_factory=list)
    output_path: str | None = None


def run_chain_analysis(session: Session) -> ChainAnalysisResult:
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before chain")

    ws_path = session.workspaces.path_for(session.workspace.name)
    dc_ip = pick_dc_ip(session)

    print_info("Attack chain analysis — cross-module prerequisites")

    chains = build_attack_chains(
        session,
        postex_ops=_load_json(ws_path / "postex_ops.json"),
        adcs_findings=_load_json(ws_path / "adcs_findings.json"),
        wsus_ops=_load_json(ws_path / "wsus_ops.json"),
        postex_scan=_load_json(ws_path / "postex_scan.json"),
        inventory=_load_json(ws_path / "auth_inventory.json"),
        dc_ip=dc_ip,
    )
    for idx, chain in enumerate(chains, start=1):
        chain.id = f"chain-{idx:03d}"

    out_path = ws_path / "chain_ops.json"
    out_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "owned_users": _owned_users(session),
                "chain_count": len(chains),
                "chains": [c.to_dict() for c in chains],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    if chains:
        rows = []
        for c in chains[:15]:
            next_step = next((s.title for s in c.steps if not s.ready), "complete")
            rows.append([c.id, c.chain_id, "yes" if c.ready else "no", c.context or "", next_step])
        print_table(
            "Attack chains",
            ["id", "chain", "ready", "context", "next_step"],
            rows,
        )
        for c in chains:
            if not c.ready and c.manual_commands:
                print_info(f"{c.id} next: {c.manual_commands[0]}")
    else:
        print_warning("no attack chains — run postex, adcs, wsus first")

    # Alert on detected correlated chains
    for c in chains:
        if c.chain_id in ("coercion_tgt_harvest_dc", "acl_abuse_kerberoast"):
            print_warning(f"attack chain: {c.title} → {c.summary}")

    print_success("attack chains saved → chain_ops.json")
    print_manual_guide("attack_chain", session=session)
    return ChainAnalysisResult(chains=chains, output_path=str(out_path))


def get_chain_op(session: Session, chain_id: str) -> dict[str, Any] | None:
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    path = session.workspaces.path_for(session.workspace.name) / "chain_ops.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data.get("chains", []):
        if str(item.get("id")) == chain_id:
            return item
    return None
