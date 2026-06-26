from __future__ import annotations

import json
from pathlib import Path

from admapper.analysis.password_rules import analyze_password_clues
from admapper.report.engagement_map import loot_clue_rows


def test_year_suffix_detection() -> None:
    clues = [
        {
            "user": "svc_sql",
            "string": "Welcome2026",
            "source": "Logs/trace.log",
            "confidence": "medium",
            "verify_state": "unverified",
        }
    ]
    result = analyze_password_clues(clues)
    rule_ids = {r["rule"] for r in result["rules"]}
    assert "year_suffix" in rule_ids
    transforms = {t["transform"] for t in result["possible_transforms"]}
    assert "adjacent_year" in transforms


def test_filename_year_mismatch_inference() -> None:
    clues = [
        {
            "user": "svc_sql",
            "string": "Welcome2025",
            "source": "Logs/IdentitySync_Trace_20260219.log",
            "confidence": "medium",
            "verify_state": "unverified",
        }
    ]
    result = analyze_password_clues(clues)
    assert any(r["rule"] == "filename_year_mismatch" for r in result["rules"])
    assert any(
        "2026" in i["reasoning"] or "2026" in i.get("label", "") for i in result["inferences"]
    )
    assert any(
        t["transform"] == "replace_trailing_year_with_filename_year"
        for t in result["possible_transforms"]
    )


def test_no_raw_password_list_in_output() -> None:
    clues = [
        {
            "user": "svc_sql",
            "string": "Welcome2026",
            "source": "Logs/IdentitySync_Trace_20260219.log",
            "confidence": "medium",
            "verify_state": "unverified",
        }
    ]
    result = analyze_password_clues(clues)
    blob = json.dumps(result)
    assert "Welcome2026" not in blob
    assert "candidates" not in blob
    assert "wordlist" not in blob
    for key in ("rules", "inferences", "possible_transforms"):
        for item in result[key]:
            assert "password" not in item


def test_loot_clue_rows_feed_rules(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "loot_manifest.json").write_text(
        json.dumps(
            {
                "parsed_credentials": [
                    {
                        "username": "svc_sql",
                        "password": "Welcome2026",
                        "source_file": "Logs/IdentitySync_Trace_20260219.log",
                        "confidence": "medium",
                    }
                ]
            }
        )
    )
    clues = loot_clue_rows(ws)
    result = analyze_password_clues(clues)
    assert result["rules"]
