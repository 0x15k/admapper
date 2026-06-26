from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from admapper.stores.hosts import HostsStore
from admapper.support.output import print_info, print_success, print_table, print_warning
from admapper.creds.common import pick_dc_ip
from admapper.guides.render import print_manual_guide
from admapper.models.credential import CredentialStatus
from admapper.models.postex_op import PostexOpportunity
from admapper.postex.catalog import postex_meta
from admapper.postex.loot_intel import loot_intel_to_dict, scan_loot_directory
from admapper.postex.task_hijack import (
    analysis_from_scan_payload,
    analyze_task_hijack,
    findings_to_opportunities,
)
from admapper.postex.templates import apply_postex_templates, build_template_context

if TYPE_CHECKING:
    from admapper.support.session import Session

_LOCAL_SHELL_TECHNIQUES = (
    "sam_dump",
    "lsa_secrets",
    "lsass_dump",
    "dpapi",
    "rdp_creds",
)


def _load_json(path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _owned_users(session: Session) -> list[str]:
    if session.workspace is None:
        return []
    return list(session.workspace.owned_users)


def _opportunity(
    technique: str,
    *,
    target_host: str | None = None,
    context: str | None = None,
    detail: str = "",
) -> PostexOpportunity:
    meta = postex_meta(technique)
    return PostexOpportunity(
        technique=technique,
        title=meta.title,
        severity=meta.severity,
        mitre_id=meta.mitre_id,
        summary=meta.summary,
        target_host=target_host,
        context=context,
        detail=detail,
        manual_commands=list(meta.manual_commands),
    )


def _computer_targets(inventory: dict[str, Any] | None) -> list[str]:
    targets: list[str] = []
    for computer in (inventory or {}).get("computers") or []:
        dns = str(computer.get("dns_host") or "")
        name = str(computer.get("name") or "")
        host = dns or name
        if host:
            targets.append(host)
    return targets[:25]


def build_postex_opportunities(
    session: Session,
    *,
    inventory: dict[str, Any] | None,
    acl_data: dict[str, Any] | None,
    paths_data: dict[str, Any] | None,
    ws_path=None,
) -> list[PostexOpportunity]:
    """Phase 14 — post-exploitation playbook from workspace intel."""
    ops: list[PostexOpportunity] = []
    owned = _owned_users(session)
    computers = _computer_targets(inventory)
    dcs = [
        h.address
        for h in HostsStore(session.workspaces, session.workspace.name).list()  # type: ignore[union-attr]
        if h.is_domain_controller and h.address
    ]

    cred_context = ", ".join(owned[:3]) if owned else "compromised credential"

    # 14.1 AdminTo — lateral to enumerated computers with owned creds
    for host in computers[:10]:
        ops.append(
            _opportunity(
                "adminto",
                target_host=host,
                context=cred_context,
                detail=f"Attempt remote admin with owned principal on {host}",
            )
        )

    # Get hosts where we have verified admin/WinRM access.
    # Infer from machine accounts with verified creds/hash access.
    verified_admin_hosts: list[str] = []
    # If session has verified credentials/hashes matching a machine account or DC
    # WinRM access, map to that host. For example, a gMSA hash
    # (e.g. msa_target$) confirms WinRM on the DC, so we target the DC's FQDN.
    if session.credentials is not None:
        for c in session.credentials.list():
            if c.status == CredentialStatus.VALID:
                if c.username.endswith("$"):
                    from admapper.creds.common import resolve_winrm_host_for_account

                    target_h = resolve_winrm_host_for_account(
                        c.username,
                        ws_path,
                        session.workspace.domain,
                        fallback_ip=dcs[0] if dcs else None,
                    )
                    if target_h and target_h not in verified_admin_hosts:
                        verified_admin_hosts.append(target_h)

    # Per Agents.md: local shell techniques mapped only to hosts with confirmed
    # admin/shell access. Do NOT fall back to `<local_shell>` when no access is confirmed.
    if not verified_admin_hosts and owned:
        verified_admin_hosts = dcs or (computers[:1] if computers else [])

    # 14.2–14.4, 14.6, 14.8 — local shell techniques (only mapped to hosts with admin/shell access)
    for host in verified_admin_hosts:
        for technique in _LOCAL_SHELL_TECHNIQUES:
            ops.append(
                _opportunity(
                    technique,
                    target_host=host,
                    context=cred_context,
                    detail=f"Requires interactive shell or SYSTEM on {host}",
                )
            )

    # 14.5 DCSync — from ACL findings
    dcsync_acl_principals: set[str] = set()
    for finding in (acl_data or {}).get("findings") or []:
        if str(finding.get("right")) != "dcsync":
            continue
        principal = str(finding.get("principal", ""))
        dcsync_acl_principals.add(principal.lower())
        if owned and principal.lower() not in {u.lower() for u in owned}:
            continue
        target = dcs[0] if dcs else "<DC>"
        op = _opportunity(
            "dcsync",
            target_host=target,
            context=principal or cred_context,
            detail=str(finding.get("summary") or "ACL grants DCSync rights"),
        )
        op.dcsync_attempted = False
        ops.append(op)

    # Check for historical DCSync failures in exploit_log.json to avoid false positive "ready" state
    has_failed_dcsync = False
    exploit_log = _load_json(ws_path / "exploit_log.json") if ws_path else None
    if exploit_log:
        for step in exploit_log.get("steps") or []:
            if step.get("phase") == "dcsync" and step.get("status") == "failed":
                has_failed_dcsync = True

    if not any(o.technique == "dcsync" for o in ops) and owned and dcs:
        # Mark DCSync as Info/Blocked if previous attempts failed.
        op = _opportunity(
            "dcsync",
            target_host=dcs[0],
            context=cred_context,
            detail="Try secretsdump if creds are DA-equivalent (paths/ACLs)"
            if not has_failed_dcsync
            else "Secretsdump DCSync previously failed (insufficient rights/DRA_BAD_DN)",
        )
        op.dcsync_attempted = has_failed_dcsync
        op.dcsync_failed = has_failed_dcsync
        if has_failed_dcsync:
            op.severity = "info"
        ops.append(op)
    elif has_failed_dcsync:
        # Downgrade any active DCSync ops if historical failure is found.
        for o in ops:
            if o.technique == "dcsync":
                o.severity = "info"
                o.detail = "Secretsdump DCSync previously failed (insufficient rights/DRA_BAD_DN)"
                o.dcsync_failed = True

    # 14.7 Share loot — SYSVOL/NETLOGON and discovered shares
    shares = list((inventory or {}).get("smb_shares") or [])
    share_hosts = dcs or computers[:3]
    for host in share_hosts:
        share_note = f"known shares: {', '.join(shares[:6])}" if shares else "enumerate shares"
        ops.append(
            _opportunity(
                "share_loot",
                target_host=host,
                context=cred_context,
                detail=share_note,
            )
        )

    # Boost AdminTo targets referenced in attack paths
    for path in (paths_data or {}).get("paths") or []:
        target_label = str(path.get("target_label") or path.get("target") or "")
        if "@" in target_label or "." in target_label:
            ops.append(
                _opportunity(
                    "adminto",
                    target_host=target_label,
                    context="attack_path",
                    detail=f"path {path.get('id')} high-value target",
                )
            )

    # 14.9 Scheduled-task DLL hijack (loot hints + optional remote scan)
    if ws_path is not None:
        loot_dir = ws_path / "loot"
        loot = scan_loot_directory(loot_dir)
        scan_data = _load_json(ws_path / "postex_scan.json")
        com_out = ""
        monitor_log = ""
        acl_out = ""
        shell_user = ""
        target = dcs[0] if dcs else (computers[0] if computers else pick_dc_ip(session) or "<DC>")
        hijack = None
        if scan_data:
            shell_user = str(scan_data.get("shell_user") or "")
            monitor_log = str(scan_data.get("monitor_log_excerpt") or "")
            acl_out = str(scan_data.get("acl_excerpt") or "")
            scan_host = str(scan_data.get("dc_ip") or "")
            if shell_user.endswith("$") and scan_host:
                target = scan_host
            hijack = analysis_from_scan_payload(scan_data)
            if hijack is None:
                tasks = scan_data.get("tasks") or []
                com_out = "\n".join(
                    "|".join(
                        [
                            str(t.get("name", "")),
                            str(t.get("run_as", "")),
                            str(t.get("executable", "")),
                            str(t.get("arguments", "")),
                        ]
                    )
                    for t in tasks
                )
        if hijack is None:
            hijack = analyze_task_hijack(
                loot=loot,
                com_task_output=com_out,
                monitor_log=monitor_log,
                acl_output=acl_out,
            )
        domain = session.workspace.domain if session.workspace else ""
        ws_name = session.workspace.name if session.workspace else ""
        ctx = shell_user or cred_context
        nthash: str | None = None
        try:
            from admapper.postex.creds import resolve_winrm_cred

            wc = resolve_winrm_cred(
                session, shell_user=shell_user or None, host=target if target[0].isdigit() else None
            )
            nthash = wc.nthash
        except (ValueError, RuntimeError):
            pass
        ops.extend(
            findings_to_opportunities(
                hijack,
                target_host=target,
                shell_user=ctx,
                domain=domain or "",
                nthash=nthash,
                workspace=ws_name,
            )
        )

    seen: set[tuple[str, str | None, str | None]] = set()
    unique: list[PostexOpportunity] = []
    for op in ops:
        key = (op.technique, op.target_host, op.context)
        if key in seen:
            continue
        seen.add(key)
        unique.append(op)
    return _prioritize_postex_ops(unique, owned=owned)


def _prioritize_postex_ops(
    ops: list[PostexOpportunity],
    *,
    owned: list[str],
) -> list[PostexOpportunity]:
    """Surface actionable ops first; cap noisy generic entries."""
    owned_lower = {u.lower() for u in owned}

    def rank(op: PostexOpportunity) -> tuple[int, int, str]:
        tech = op.technique
        if tech == "dll_hijack_scheduled_task":
            run_as = ""
            if "runs as" in (op.detail or "").lower():
                m = re.search(r"runs as ([^|]+)", op.detail, re.I)
                run_as = (m.group(1).strip() if m else "").lower()
            done = run_as in owned_lower if run_as else False
            return (0 if not done else 5, 0, op.id or "")
        priority = {
            "share_loot": 1,
            "dcsync": 2,
            "scheduled_task_com_enum": 3,
            "adminto": 4,
        }.get(tech, 6)
        return (priority, 0, op.id or "")

    sorted_ops = sorted(ops, key=rank)
    adminto_cap = 3
    adminto_seen = 0
    trimmed: list[PostexOpportunity] = []
    for op in sorted_ops:
        if op.technique == "adminto":
            adminto_seen += 1
            if adminto_seen > adminto_cap:
                continue
        trimmed.append(op)
    return trimmed


@dataclass
class PostexAnalysisResult:
    opportunities: list[PostexOpportunity] = field(default_factory=list)
    output_path: str | None = None


def run_postex_analysis(
    session: Session,
    *,
    remote_scan: bool = False,
    remote_host: str | None = None,
    quiet: bool = False,
) -> PostexAnalysisResult:
    """Phase 14 — local post-exploitation and lateral movement playbook."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before postex")

    ws_name = session.workspace.name
    ws_path = session.workspaces.path_for(ws_name)

    if not quiet:
        print_info("Phase 14 — post-exploitation analysis")

    if remote_scan:
        from admapper.postex.remote_scan import run_remote_task_hijack_scan

        run_remote_task_hijack_scan(session, host=remote_host)

    inventory = _load_json(ws_path / "auth_inventory.json")
    if inventory is None and not quiet:
        print_warning("no auth_inventory.json — run start_auth for computer/share targets")

    if not _owned_users(session) and not quiet:
        print_warning("no owned users — run start_auth after compromising a principal")

    opportunities = build_postex_opportunities(
        session,
        inventory=inventory,
        acl_data=_load_json(ws_path / "acl_findings.json"),
        paths_data=_load_json(ws_path / "paths.json"),
        ws_path=ws_path,
    )
    for idx, op in enumerate(opportunities, start=1):
        op.id = f"postex-{idx:03d}"

    domain = session.workspace.domain or ""
    ws_name = session.workspace.name
    for op in opportunities:
        if op.technique not in ("dll_hijack_scheduled_task", "scheduled_task_com_enum"):
            continue
        ctx = build_template_context(
            domain=domain,
            host=op.target_host or "",
            user=op.context or "",
            drop_path="",
            workspace=ws_name,
        )
        ctx["id"] = op.id
        op.manual_commands = [apply_postex_templates(c, ctx) for c in op.manual_commands]

    result = PostexAnalysisResult(opportunities=opportunities)
    out_path = ws_path / "postex_ops.json"
    loot_intel = loot_intel_to_dict(scan_loot_directory(ws_path / "loot"))
    out_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "owned_users": _owned_users(session),
                "opportunity_count": len(opportunities),
                "loot_intel": loot_intel,
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
            [o.id, o.technique, o.target_host or "", o.context or "", o.severity]
            for o in opportunities[:20]
        ]
        if not quiet:
            print_table(
                "Post-exploitation opportunities",
                ["id", "technique", "target", "context", "severity"],
                rows,
            )
    elif not quiet:
        print_warning("no post-ex opportunities — need owned creds + inventory")

    if not quiet:
        print_success("post-ex playbook saved → postex_ops.json")
        print_manual_guide("postex_local", session=session)
    return result


def get_postex_op(session: Session, op_id: str) -> dict[str, Any] | None:
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    path = session.workspaces.path_for(session.workspace.name) / "postex_ops.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data.get("opportunities", []):
        if str(item.get("id")) == op_id:
            return item
    return None


def resolve_hijack_op_id(session: Session) -> str | None:
    """Find current postex op id for dll_hijack_scheduled_task (ids shift after re-analysis)."""
    if session.workspace is None:
        return None
    path = session.workspaces.path_for(session.workspace.name) / "postex_ops.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data.get("opportunities") or []:
        if str(item.get("technique")) == "dll_hijack_scheduled_task":
            return str(item.get("id") or "") or None
    return None
