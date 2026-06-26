from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from admapper.models.finding import Finding
from admapper.models.report_item import ReportItem

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _norm_severity(value: str | None) -> str:
    raw = str(value or "info").lower()
    if raw in _SEVERITY_ORDER:
        return raw
    return "info"


def _item_from_finding(raw: dict[str, Any], *, source: str, category: str) -> ReportItem:
    title = str(
        raw.get("title") or raw.get("summary") or raw.get("right") or raw.get("esc") or "finding"
    )
    detail = str(
        raw.get("detail")
        or raw.get("summary")
        or raw.get("target_name")
        or raw.get("template")
        or ""
    )
    host = raw.get("host") or raw.get("target_host") or raw.get("listener_host")
    technique = raw.get("technique") or raw.get("key") or raw.get("right") or raw.get("esc")
    return ReportItem(
        category=category,
        title=title,
        severity=_norm_severity(raw.get("severity")),
        source=source,
        detail=detail,
        item_id=str(raw.get("id")) if raw.get("id") else None,
        mitre_id=raw.get("mitre_id"),
        host=str(host) if host else None,
        technique=str(technique) if technique else None,
        extra={
            k: v
            for k, v in raw.items()
            if k not in {"id", "title", "severity", "summary", "detail"}
        },
    )


@dataclass
class CollectedReport:
    items: list[ReportItem] = field(default_factory=list)
    paths: list[dict[str, Any]] = field(default_factory=list)
    quick_wins: list[dict[str, Any]] = field(default_factory=list)
    sources_present: list[str] = field(default_factory=list)


def collect_workspace_report(ws_path: Path) -> CollectedReport:
    """Aggregate findings and playbooks from all workspace JSON artefacts."""
    report = CollectedReport()

    findings_data = _load_json(ws_path / "findings.json")
    if findings_data:
        report.sources_present.append("findings.json")
        for raw in findings_data.get("findings") or []:
            finding = Finding.from_dict(raw)
            report.items.append(
                ReportItem(
                    category="recon",
                    title=finding.title,
                    severity=finding.severity.value,
                    source="findings.json",
                    detail=finding.detail,
                    item_id=finding.id,
                    mitre_id=finding.mitre_id,
                    host=finding.host,
                    technique=finding.key,
                )
            )

    artifact_specs: list[tuple[str, str, str]] = [
        ("acl_findings.json", "acl", "findings"),
        ("adcs_findings.json", "adcs", "findings"),
        ("kerberos_ops.json", "kerberos", "opportunities"),
        ("coerce_ops.json", "coerce", "opportunities"),
        ("postex_ops.json", "postex", "opportunities"),
        ("wsus_ops.json", "wsus", "opportunities"),
        ("escalate.json", "escalate", "edges"),
        ("mssql_findings.json", "mssql", "findings"),
        ("cve_findings.json", "cve", "findings"),
    ]

    for filename, category, key in artifact_specs:
        data = _load_json(ws_path / filename)
        if data is None:
            continue
        report.sources_present.append(filename)
        for raw in data.get(key) or []:
            if isinstance(raw, dict):
                report.items.append(_item_from_finding(raw, source=filename, category=category))

    paths_data = _load_json(ws_path / "paths.json")
    if paths_data:
        report.sources_present.append("paths.json")
        report.paths = list(paths_data.get("paths") or [])
        report.quick_wins = list(paths_data.get("quick_wins") or [])
        for path in report.paths:
            report.items.append(
                ReportItem(
                    category="paths",
                    title=f"Attack path {path.get('id', '')}",
                    severity=_norm_severity(path.get("impact")),
                    source="paths.json",
                    detail=str(path.get("summary") or ""),
                    item_id=str(path.get("id")) if path.get("id") else None,
                    mitre_id="T1068",
                    technique="attack_path",
                    extra={"length": path.get("length"), "target": path.get("target")},
                )
            )
        for win in report.quick_wins:
            report.items.append(
                ReportItem(
                    category="quick_wins",
                    title=str(win.get("title") or "quick win"),
                    severity=_norm_severity(win.get("severity")),
                    source="paths.json",
                    detail=str(win.get("detail") or ""),
                    mitre_id=win.get("mitre_id"),
                    technique=str(win.get("key") or "quick_win"),
                )
            )

    report.items.sort(
        key=lambda item: (
            _SEVERITY_ORDER.index(item.severity)
            if item.severity in _SEVERITY_ORDER
            else len(_SEVERITY_ORDER),
            item.category,
            item.title,
        )
    )
    return report
