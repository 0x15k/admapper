from __future__ import annotations

import json
from pathlib import Path

from admapper.methodology.unified import (
    ENGAGEMENT_FRAMEWORK,
    OPS_PHASES,
    UNIFIED_PHASES,
    build_study_map,
    ops_phase_status,
    methodology_progress_lines,
    phase_status_from_workspace,
)


def test_unified_has_twelve_phases() -> None:
    assert len(UNIFIED_PHASES) == 12
    assert len(OPS_PHASES) == 9
    assert "CRTP" in ENGAGEMENT_FRAMEWORK


def test_study_map_covers_all_phases() -> None:
    sm = build_study_map()
    assert len(sm) == 12
    assert sm[4]["name"] == "Foothold"
    assert sm[4]["crtp"] == "Assumed breach"


def test_phase_status_progression(tmp_path: Path) -> None:
    ws = tmp_path
    (ws / "state.json").write_text(json.dumps({"hosts": "10.0.0.1"}))
    (ws / "unauth_scan.json").write_text(json.dumps({"hosts": [{"address": "10.0.0.1"}]}))
    st = phase_status_from_workspace(ws)
    assert st["p02"] == "done"
    assert st["p05"] == "active"

    (ws / "credentials.json").write_text(
        json.dumps({"credentials": [{"username": "alice", "status": "valid"}]})
    )
    st2 = phase_status_from_workspace(ws)
    assert st2["p05"] == "done"


def test_ops_phases_include_framework(tmp_path: Path) -> None:
    ws = tmp_path
    (ws / "state.json").write_text("{}")
    (ws / "unauth_scan.json").write_text(json.dumps({"hosts": [{}]}))
    phases = ops_phase_status(ws)
    assert phases[0]["code"] == "RECON"
    assert "framework" in phases[0]
    assert phases[0]["framework"]["crtp"]


def test_methodology_lines_use_unified(tmp_path: Path) -> None:
    ws = tmp_path
    (ws / "unauth_scan.json").write_text(json.dumps({"hosts": [{}]}))
    lines = methodology_progress_lines(ws)
    assert any("AD CHAIN" in ln for ln in lines)
    assert any("P02" in ln for ln in lines)
