from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from admapper import __version__
from admapper.report.collect import CollectedReport
from admapper.report.summary import build_summary


def build_evidence_txt(
    collected: CollectedReport,
    *,
    workspace: str,
    domain: str | None,
) -> str:
    """Phase 17.1 — human-readable evidence report."""
    summary = build_summary(collected.items)
    lines = [
        "ADMapper Evidence Report (appendix)",
        "=" * 60,
        f"Workspace: {workspace}",
        f"Domain:    {domain or '(not set)'}",
        f"Generated: {datetime.now(UTC).isoformat()}",
        f"Version:   {__version__}",
        "",
        "Read engagement_summary.txt first — this file lists every finding including",
        "unverified CVE/coercion candidates deferred from the main narrative.",
        "",
        "Summary",
        "-" * 60,
        f"Total findings: {summary['total_items']}",
    ]
    for severity, count in sorted(summary.get("by_severity", {}).items()):
        lines.append(f"  {severity}: {count}")
    lines.append("")
    lines.append("By category")
    for category, count in sorted(summary.get("by_category", {}).items()):
        lines.append(f"  {category}: {count}")
    if summary.get("mitre_techniques"):
        lines.append("")
        lines.append("MITRE techniques")
        lines.append(", ".join(summary["mitre_techniques"]))
    lines.append("")
    lines.append("Findings")
    lines.append("-" * 60)

    current_category = ""
    for item in collected.items:
        if item.category != current_category:
            current_category = item.category
            lines.append("")
            lines.append(f"[{current_category.upper()}]")
        host_part = f" @ {item.host}" if item.host else ""
        mitre_part = f" [{item.mitre_id}]" if item.mitre_id else ""
        lines.append(f"- [{item.severity}] {item.title}{host_part}{mitre_part}")
        if item.detail:
            lines.append(f"    {item.detail}")
        if item.item_id:
            lines.append(f"    id: {item.item_id}  source: {item.source}")

    if collected.paths:
        lines.append("")
        lines.append("Attack paths")
        lines.append("-" * 60)
        for path in collected.paths[:25]:
            lines.append(
                f"- {path.get('id')}: {path.get('source')} → {path.get('target')} "
                f"({path.get('length')} hops, {path.get('impact')})"
            )

    lines.append("")
    return "\n".join(lines) + "\n"


def write_evidence_txt(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path
