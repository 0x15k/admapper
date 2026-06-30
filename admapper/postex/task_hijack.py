from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from admapper.models.postex_op import PostexOpportunity
from admapper.postex.catalog import postex_meta
from admapper.postex.hijack_intel import (
    UNKNOWN_DROP_PATH,
    extract_hijack_intel,
    guess_run_as_from_log,
    intel_from_com_tasks,
    is_system_run_as,
)
from admapper.postex.loot_intel import LootIntelResult
from admapper.postex.nxc_output import strip_nxc_winrm_output
from admapper.postex.pe_arch import TargetArch, infer_arch_from_monitor_log, normalize_arch
from admapper.postex.task_run_as import is_interactive_task_user, resolve_task_run_as
from admapper.postex.templates import apply_postex_templates, build_template_context

_WRITABLE_RE = re.compile(
    r"\(WD|\(W\)|\(M\)|\(F\)|\(AD\)|\(WEA\)|\(WA\)",
    re.I,
)
_PAYLOAD_REF_RE = re.compile(r"\.zip|\.dll", re.I)
_SYSTEM_HIJACK_NOTE = "Runs as SYSTEM — value is persistence, not escalation"
_UNKNOWN_DROP_EVIDENCE = (
    "loot: zip+dll confirmed but drop path could not be parsed — verify manually"
)


@dataclass
class ScheduledTaskRecord:
    name: str
    run_as: str = ""
    executable: str = ""
    arguments: str = ""
    state: str = ""


@dataclass
class TaskHijackFinding:
    task_name: str
    run_as_user: str
    executable: str
    arguments: str
    drop_path: str
    payload_zip: str
    payload_dll: str
    writable: bool
    target_arch: str = "x64"
    evidence: list[str] = field(default_factory=list)
    severity: str = "high"


@dataclass
class TaskHijackAnalysis:
    findings: list[TaskHijackFinding] = field(default_factory=list)
    tasks: list[ScheduledTaskRecord] = field(default_factory=list)
    monitor_log_excerpt: str = ""
    acl_excerpt: str = ""
    hijack_intel: dict[str, Any] = field(default_factory=dict)


def _parse_com_task_lines(output: str) -> list[ScheduledTaskRecord]:
    text = strip_nxc_winrm_output(output)
    records: list[ScheduledTaskRecord] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|", 3)
        while len(parts) < 4:
            parts.append("")
        name, user, exe, args = parts[0], parts[1], parts[2], parts[3]
        name = name.strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        user = user.strip()
        if "\\" in user:
            user = user.split("\\", 1)[1]
        records.append(
            ScheduledTaskRecord(
                name=name,
                run_as=user,
                executable=exe.strip(),
                arguments=args.strip(),
            )
        )
    return records


def _unique_loot_tasks(loot: LootIntelResult | None) -> list[ScheduledTaskRecord]:
    if not loot:
        return []
    seen: set[str] = set()
    out: list[ScheduledTaskRecord] = []
    for hint in loot.task_hints:
        key = hint.task_name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(ScheduledTaskRecord(name=hint.task_name))
    return out


def _hijack_finding_severity(
    *,
    run_as: str,
    writable: bool,
    strong_loot_hints: bool,
    drop_path: str,
) -> str:
    """Severity for a scheduled-task DLL hijack candidate."""
    if is_system_run_as(run_as):
        return "medium"
    if drop_path == UNKNOWN_DROP_PATH:
        return "high"
    if writable and run_as != "unknown":
        return "critical"
    if strong_loot_hints:
        return "high"
    return "info"


def analyze_task_hijack(
    *,
    loot: LootIntelResult | None,
    com_task_output: str = "",
    monitor_log: str = "",
    acl_output: str = "",
    target_arch: str | None = None,
    discovered_monitor_log_path: str | None = None,
) -> TaskHijackAnalysis:
    """Detect scheduled-task DLL hijack from loot, COM tasks, monitor logs, and ACLs."""
    tasks = _parse_com_task_lines(com_task_output)
    intel = extract_hijack_intel(loot, monitor_log=monitor_log, com_task_output=com_task_output)
    if intel is None and com_task_output.strip():
        intel = intel_from_com_tasks(com_task_output)
    from admapper.postex.hijack_intel import with_discovered_monitor_log_path

    intel = with_discovered_monitor_log_path(intel, discovered_monitor_log_path)
    monitor_log_path = (
        intel.monitor_log_path if intel else None
    ) or (str(discovered_monitor_log_path or "").strip() or None)
    analysis = TaskHijackAnalysis(
        tasks=tasks,
        monitor_log_excerpt=monitor_log.strip()[:2000],
        acl_excerpt=acl_output.strip()[:1000],
        hijack_intel={
            "payload_zip": intel.payload_zip if intel else None,
            "payload_dll": intel.payload_dll if intel else None,
            "drop_path": intel.drop_path if intel else None,
            "monitor_log_path": monitor_log_path,
            "task_name_hint": intel.task_name_hint if intel else None,
            "task_run_as_user": None,
        },
    )
    if intel is None:
        return analysis

    candidate_tasks = list(tasks)
    if intel.task_name_hint:
        hinted = [t for t in candidate_tasks if intel.task_name_hint.lower() in t.name.lower()]
        if hinted:
            candidate_tasks = hinted
    if not candidate_tasks:
        candidate_tasks = _unique_loot_tasks(loot)
    if not candidate_tasks and intel.task_name_hint:
        candidate_tasks = [ScheduledTaskRecord(name=intel.task_name_hint)]

    zip_tasks = [
        t for t in candidate_tasks if _PAYLOAD_REF_RE.search(f"{t.executable} {t.arguments}")
    ]
    if zip_tasks:
        candidate_tasks = zip_tasks

    writable = bool(_WRITABLE_RE.search(acl_output))
    arch: TargetArch = (
        normalize_arch(target_arch) or infer_arch_from_monitor_log(monitor_log) or "x64"
    )
    zip_name = intel.payload_zip
    dll_name = intel.payload_dll
    drop_path = intel.drop_path

    # If we have strong loot hints but no remote ACL proof, still surface a
    # high-severity finding so the operator can verify with postex scan.
    strong_loot_hints = bool(
        loot
        and (
            bool(loot.zip_dll_refs)
            or bool(loot.dll_hijack_refs)
            or (bool(intel.payload_zip) and bool(intel.payload_dll))
        )
    )

    seen_findings: set[str] = set()
    for task in candidate_tasks:
        run_as = task.run_as or guess_run_as_from_log(monitor_log) or "unknown"
        if not is_interactive_task_user(run_as):
            resolved = resolve_task_run_as(
                {
                    "tasks": [
                        {
                            "name": t.name,
                            "run_as": t.run_as,
                            "executable": t.executable,
                            "arguments": t.arguments,
                        }
                        for t in tasks
                    ],
                    "com_task_raw": com_task_output,
                },
                {
                    "run_as_user": run_as,
                    "task_name": task.name,
                    "payload_zip": zip_name,
                },
            )
            if resolved != "unknown":
                run_as = resolved
        finding_key = task.name.lower()
        if finding_key in seen_findings:
            continue
        seen_findings.add(finding_key)

        exe = task.executable or ""
        evidence: list[str] = []
        if loot:
            for hint in loot.task_hints:
                if hint.task_name.lower() == task.name.lower():
                    evidence.append(f"loot/{hint.source_file}: {hint.line[:120]}")
                    break
            if loot.dll_hijack_refs:
                evidence.append(loot.dll_hijack_refs[0][:160])
        if monitor_log:
            evidence.append("remote: service log references zip/dll load path")
        if writable:
            evidence.append(f"remote: {drop_path} writable by current principal")
        if drop_path == UNKNOWN_DROP_PATH:
            evidence.append(_UNKNOWN_DROP_EVIDENCE)
        elif not writable and strong_loot_hints:
            evidence.append("loot: zip+dll+drop path detected — verify ACL with postex scan")
        if is_system_run_as(run_as):
            evidence.append(_SYSTEM_HIJACK_NOTE)

        severity = _hijack_finding_severity(
            run_as=run_as,
            writable=writable,
            strong_loot_hints=strong_loot_hints,
            drop_path=drop_path,
        )

        if writable or strong_loot_hints:
            analysis.findings.append(
                TaskHijackFinding(
                    task_name=task.name,
                    run_as_user=run_as,
                    executable=exe,
                    arguments=task.arguments,
                    drop_path=drop_path,
                    payload_zip=zip_name,
                    payload_dll=dll_name,
                    writable=writable,
                    target_arch=arch,
                    evidence=evidence,
                    severity=severity,
                )
            )

    if not analysis.findings:
        run_as = guess_run_as_from_log(monitor_log) or guess_run_as_from_log(com_task_output)
        task_name = intel.task_name_hint or "scheduled_task"
        for line in com_task_output.splitlines():
            if "|" not in line:
                continue
            parts = line.split("|", 3)
            user = parts[1].strip() if len(parts) > 1 else ""
            if user and not user.endswith("$"):
                run_as = user.split("\\", 1)[-1] if "\\" in user else user
            if parts[0].strip():
                task_name = parts[0].strip()
                break
        evidence = []
        if monitor_log:
            evidence.append("remote: service log references zip/dll load path")
        if drop_path == UNKNOWN_DROP_PATH:
            evidence.append(_UNKNOWN_DROP_EVIDENCE)
        elif strong_loot_hints:
            evidence.append("loot: zip+dll+drop path detected — verify ACL with postex scan")
        run_as_resolved = run_as or "unknown"
        if is_system_run_as(run_as_resolved):
            evidence.append(_SYSTEM_HIJACK_NOTE)
        severity = _hijack_finding_severity(
            run_as=run_as_resolved,
            writable=writable,
            strong_loot_hints=strong_loot_hints,
            drop_path=drop_path,
        )
        if writable or strong_loot_hints:
            analysis.findings.append(
                TaskHijackFinding(
                    task_name=task_name,
                    run_as_user=run_as_resolved,
                    executable="",
                    arguments="",
                    drop_path=drop_path,
                    payload_zip=zip_name,
                    payload_dll=dll_name,
                    writable=writable,
                    target_arch=arch,
                    evidence=evidence,
                    severity=severity,
                )
            )
    if analysis.findings:
        analysis.hijack_intel["task_run_as_user"] = analysis.findings[0].run_as_user
    return analysis


def analysis_from_scan_payload(
    scan_data: dict[str, Any],
    *,
    ws_path: Path | None = None,
) -> TaskHijackAnalysis | None:
    """Rebuild TaskHijackAnalysis from postex_scan.json findings (scenario/remote scan)."""
    raw = scan_data.get("findings") or []
    if not raw:
        return None
    findings: list[TaskHijackFinding] = []
    for item in raw:
        run_as = resolve_task_run_as(scan_data, item, ws_path=ws_path)
        findings.append(
            TaskHijackFinding(
                task_name=str(item.get("task_name") or ""),
                run_as_user=run_as,
                executable=str(item.get("executable") or ""),
                arguments=str(item.get("arguments") or ""),
                drop_path=str(item.get("drop_path") or ""),
                payload_zip=str(item.get("payload_zip") or ""),
                payload_dll=str(item.get("payload_dll") or ""),
                writable=bool(item.get("writable")),
                target_arch=str(item.get("target_arch") or "x64"),
                evidence=list(item.get("evidence") or []),
                severity=str(item.get("severity") or "high"),
            )
        )
    return TaskHijackAnalysis(
        findings=findings,
        monitor_log_excerpt=str(scan_data.get("monitor_log_excerpt") or "")[:2000],
        acl_excerpt=str(scan_data.get("acl_excerpt") or "")[:1000],
        hijack_intel={
            **dict(scan_data.get("hijack_intel") or {}),
            "task_run_as_user": findings[0].run_as_user if findings else None,
        },
    )


def findings_to_opportunities(
    analysis: TaskHijackAnalysis,
    *,
    target_host: str,
    shell_user: str,
    domain: str = "",
    nthash: str | None = None,
    workspace: str = "",
) -> list[PostexOpportunity]:
    ops: list[PostexOpportunity] = []
    for finding in analysis.findings:
        meta = postex_meta("dll_hijack_scheduled_task")
        ctx = build_template_context(
            domain=domain,
            host=target_host,
            user=shell_user,
            nthash=nthash,
            drop_path=finding.drop_path,
            payload_zip=finding.payload_zip,
            payload_dll=finding.payload_dll,
            task_name=finding.task_name,
            run_as=finding.run_as_user,
            workspace=workspace,
        )
        detail_parts = [
            f"Task '{finding.task_name}' runs as {finding.run_as_user}",
        ]
        if (
            shell_user
            and finding.run_as_user
            and shell_user.lower().rstrip("$") != finding.run_as_user.lower().rstrip("$")
        ):
            detail_parts.insert(
                0,
                f"Escalation: {shell_user} → {finding.run_as_user} via scheduled-task DLL hijack",
            )
        detail_parts.extend(
            [
            f"Binary: {finding.executable} {finding.arguments}".strip(),
            f"Drop {finding.payload_zip} (contains {finding.payload_dll}) → {finding.drop_path}",
            ]
        )
        if finding.writable:
            detail_parts.append("Drop path writable — deploy payload and wait for task trigger")
        else:
            detail_parts.append("Confirm ACLs on drop path after shell access")
        if is_system_run_as(finding.run_as_user):
            detail_parts.append(_SYSTEM_HIJACK_NOTE)

        commands = [apply_postex_templates(c, ctx) for c in meta.manual_commands]

        ops.append(
            PostexOpportunity(
                technique="dll_hijack_scheduled_task",
                title=meta.title,
                severity=finding.severity,
                mitre_id=meta.mitre_id,
                summary=apply_postex_templates(meta.summary, ctx),
                target_host=target_host,
                context=shell_user,
                detail=" | ".join(detail_parts),
                manual_commands=commands,
            )
        )

        enum_meta = postex_meta("scheduled_task_com_enum")
        if not any(o.technique == "scheduled_task_com_enum" for o in ops):
            enum_cmds = [apply_postex_templates(c, ctx) for c in enum_meta.manual_commands]
            ops.append(
                PostexOpportunity(
                    technique="scheduled_task_com_enum",
                    title=enum_meta.title,
                    severity=enum_meta.severity,
                    mitre_id=enum_meta.mitre_id,
                    summary=enum_meta.summary,
                    target_host=target_host,
                    context=shell_user,
                    detail="CIM/schtasks denied — enumerate via Task Scheduler COM API",
                    manual_commands=enum_cmds,
                )
            )
    return ops


def analysis_to_dict(analysis: TaskHijackAnalysis) -> dict[str, Any]:
    return {
        "findings": [
            {
                "task_name": f.task_name,
                "run_as_user": f.run_as_user,
                "executable": f.executable,
                "arguments": f.arguments,
                "drop_path": f.drop_path,
                "payload_zip": f.payload_zip,
                "payload_dll": f.payload_dll,
                "writable": f.writable,
                "target_arch": f.target_arch,
                "evidence": f.evidence,
                "severity": f.severity,
            }
            for f in analysis.findings
        ],
        "tasks": [
            {
                "name": t.name,
                "run_as": t.run_as,
                "executable": t.executable,
                "arguments": t.arguments,
            }
            for t in analysis.tasks
        ],
        "monitor_log_excerpt": analysis.monitor_log_excerpt,
        "acl_excerpt": analysis.acl_excerpt,
        "monitor_log_path": (analysis.hijack_intel or {}).get("monitor_log_path"),
        "task_run_as_user": (analysis.hijack_intel or {}).get("task_run_as_user"),
        "hijack_intel": analysis.hijack_intel,
    }
