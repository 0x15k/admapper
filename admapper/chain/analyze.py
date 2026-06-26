from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from admapper.support.output import print_info, print_success, print_table, print_warning
from admapper.creds.common import pick_dc_ip
from admapper.guides.render import print_manual_guide
from admapper.models.chain_op import ChainOpportunity, ChainStep
from admapper.wsus.prerequisites import owned_groups_for_user

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
                detail=f"Enroll {template} as {pivot}" if template else "Run adcs after owning pivot user",
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
            commands.append("certipy find -u <user>@<domain> -hashes :<NTLM> -dc-ip <DC> -vulnerable")
        elif enroll_ready and not wsus_ready:
            commands.append(f"admapper wsus -w <workspace>")
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
