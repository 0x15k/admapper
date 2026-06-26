import json
from pathlib import Path

from admapper.core.config import GlobalConfig
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.models.finding import Finding, FindingSeverity
from admapper.core.findings import FindingsStore
from admapper.report.collect import collect_workspace_report
from admapper.report.export import run_export
from admapper.report.navigator import build_navigator_layer


def _seed_workspace(tmp_path: Path) -> Path:
    ws_path = tmp_path / "ws" / "lab"
    ws_path.mkdir(parents=True)

    findings_store = FindingsStore(WorkspaceManager(tmp_path / "ws"), "lab")
    findings_store.merge(
        [
            Finding(
                key="ldap_anonymous",
                title="LDAP anonymous bind",
                severity=FindingSeverity.MEDIUM,
                source="start_unauth",
                mitre_id="T1087.002",
                detail="Anonymous LDAP allowed",
            )
        ]
    )

    (ws_path / "acl_findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "acl-001",
                        "right": "genericall",
                        "principal": "jsmith",
                        "target_name": "DA_GROUP",
                        "severity": "critical",
                        "mitre_id": "T1098",
                        "summary": "GenericAll on Domain Admins group",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws_path / "paths.json").write_text(
        json.dumps(
            {
                "paths": [
                    {
                        "id": "path-001",
                        "source": "user:jsmith",
                        "target": "group:domain admins",
                        "length": 2,
                        "impact": "critical",
                        "summary": "jsmith → Domain Admins",
                    }
                ],
                "quick_wins": [
                    {
                        "key": "gpp_0",
                        "title": "GPP password",
                        "severity": "high",
                        "detail": "admin:Password123",
                        "mitre_id": "T1552.006",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return ws_path


def test_collect_workspace_report_aggregates_sources(tmp_path: Path) -> None:
    ws_path = _seed_workspace(tmp_path)
    collected = collect_workspace_report(ws_path)

    categories = {item.category for item in collected.items}
    assert "recon" in categories
    assert "acl" in categories
    assert "paths" in categories
    assert "quick_wins" in categories
    assert len(collected.sources_present) >= 3


def test_build_navigator_layer_scores_techniques(tmp_path: Path) -> None:
    ws_path = _seed_workspace(tmp_path)
    collected = collect_workspace_report(ws_path)
    layer = build_navigator_layer(collected.items, workspace="lab", domain="target.example")

    technique_ids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1087.002" in technique_ids
    assert "T1098" in technique_ids
    assert layer["domain"] == "enterprise-attack"


def test_run_export_writes_all_artifacts(tmp_path: Path) -> None:
    _seed_workspace(tmp_path)
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")

    result = run_export(session)

    ws_path = tmp_path / "ws" / "lab"
    assert result.item_count > 0
    assert (ws_path / "evidence_export.json").is_file()
    assert (ws_path / "technical_report.json").is_file()
    assert (ws_path / "evidence_report.txt").is_file()
    assert (ws_path / "mitre_navigator_layer.json").is_file()

    technical = json.loads((ws_path / "technical_report.json").read_text(encoding="utf-8"))
    assert technical["schema_version"] == "1.0"
    assert technical["summary"]["total_items"] == result.item_count
