from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from admapper.report.collect import collect_workspace_report
from admapper.report.engagement import build_engagement_summary, write_engagement_summary
from admapper.report.evidence import build_evidence_export, write_evidence_export
from admapper.report.html import build_engagement_html, write_engagement_html
from admapper.report.navigator import build_navigator_layer, write_navigator_layer
from admapper.report.technical import build_technical_report, write_technical_report
from admapper.report.txt import build_evidence_txt, write_evidence_txt
from admapper.support.output import print_info, print_success, print_table, print_warning

if TYPE_CHECKING:
    from admapper.support.session import Session


@dataclass
class ExportResult:
    evidence_json_path: str | None = None
    technical_json_path: str | None = None
    evidence_txt_path: str | None = None
    engagement_txt_path: str | None = None
    engagement_html_path: str | None = None
    navigator_path: str | None = None
    item_count: int = 0
    errors: list[str] = field(default_factory=list)


def run_export(
    session: Session,
    *,
    export_json: bool = True,
    export_txt: bool = True,
    export_navigator: bool = True,
    quiet: bool = False,
) -> ExportResult:
    """P12 Reporting — export evidence, technical report, and Navigator layer."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    ws_name = session.workspace.name
    domain = session.workspace.domain
    ws_path = session.workspaces.path_for(ws_name)

    if not quiet:
        from admapper.support.phases import phase_banner

        print_info(phase_banner("p12", detail="reporting export"))
    collected = collect_workspace_report(ws_path)
    result = ExportResult(item_count=len(collected.items))

    if not collected.items:
        if not quiet:
            print_warning("no findings to export — run recon and analysis phases first")
    elif not quiet:
        print_success(f"collected {len(collected.items)} report item(s)")

    if export_json:
        evidence_payload = build_evidence_export(collected, workspace=ws_name, domain=domain)
        evidence_path = write_evidence_export(ws_path / "evidence_export.json", evidence_payload)
        result.evidence_json_path = str(evidence_path)

        technical_payload = build_technical_report(collected, workspace=ws_name, domain=domain)
        technical_path = write_technical_report(
            ws_path / "technical_report.json", technical_payload
        )
        result.technical_json_path = str(technical_path)

        if not quiet:
            print_success(f"evidence JSON → {evidence_path}")
            print_success(f"technical report → {technical_path}")

    if export_txt:
        owned = list(session.workspace.owned_users or [])
        engagement_content = build_engagement_summary(
            ws_path,
            workspace=ws_name,
            domain=domain,
            owned_users=owned,
        )
        engagement_path = write_engagement_summary(
            ws_path / "engagement_summary.txt",
            engagement_content,
        )
        result.engagement_txt_path = str(engagement_path)
        if not quiet:
            print_success(f"engagement summary → {engagement_path}  ← START HERE")

        html_content = build_engagement_html(
            ws_path,
            workspace=ws_name,
            domain=domain,
            owned_users=owned,
            pivot_user=session.workspace.pivot_user,
        )
        html_path = write_engagement_html(ws_path / "engagement_report.html", html_content)
        result.engagement_html_path = str(html_path)
        if not quiet:
            print_success(f"engagement HTML → {html_path}")

        txt_content = build_evidence_txt(collected, workspace=ws_name, domain=domain)
        txt_path = write_evidence_txt(ws_path / "evidence_report.txt", txt_content)
        result.evidence_txt_path = str(txt_path)
        if not quiet:
            print_success(f"evidence appendix → {txt_path}")

    if export_navigator:
        layer = build_navigator_layer(collected.items, workspace=ws_name, domain=domain)
        nav_path = write_navigator_layer(ws_path / "mitre_navigator_layer.json", layer)
        result.navigator_path = str(nav_path)
        if not quiet:
            technique_count = len(layer.get("techniques") or [])
            print_success(f"MITRE Navigator layer → {nav_path} ({technique_count} techniques)")

    if quiet:
        if result.engagement_html_path:
            print_info(f"reportes → {result.engagement_html_path}")
    else:
        print_info(f"workspace folder: {ws_path}")
        if collected.sources_present:
            print_table(
                "Sources",
                ["artefact"],
                [[source] for source in collected.sources_present],
            )

    return result
