import json
from pathlib import Path

from admapper.report.html import build_engagement_html, write_engagement_html


def test_build_engagement_html_includes_findings(tmp_path: Path) -> None:
    ws = tmp_path / "lab"
    ws.mkdir()
    (ws / "acl_findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "acl-001",
                        "title": "GenericAll on SVC",
                        "severity": "high",
                        "principal": "user1",
                        "right": "GenericAll",
                        "target_name": "svc_sql",
                        "summary": "ACL abuse",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "credentials.json").write_text(
        json.dumps({"credentials": [{"id": "c1", "username": "user1", "status": "valid"}]}),
        encoding="utf-8",
    )

    html = build_engagement_html(
        ws,
        workspace="lab",
        domain="corp.local",
        owned_users=["user1"],
        pivot_user="user1",
    )

    assert "<!DOCTYPE html>" in html
    assert "corp.local" in html
    assert "GenericAll" in html
    assert "RECOMENDADO" in html or "Recommended actions" in html


def test_write_engagement_html(tmp_path: Path) -> None:
    path = tmp_path / "out" / "engagement_report.html"
    write_engagement_html(path, "<html><body>ok</body></html>")
    assert path.is_file()
    assert "ok" in path.read_text(encoding="utf-8")
