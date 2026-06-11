from pathlib import Path

from admapper.creds.password_candidates import (
    build_password_candidates_file,
    propose_password_candidates,
)


def test_propose_year_variants_for_stale_log() -> None:
    cands = propose_password_candidates("Em3rg3ncyPa$$2025", stale_log=True, confidence="medium")
    passwords = [c.password for c in cands]
    assert "Em3rg3ncyPa$$2025" in passwords
    assert "Em3rg3ncyPa$$2026" in passwords
    reasons = {c.reason for c in cands}
    assert "parsed_from_loot" in reasons
    assert "stale_log_year_variant" in reasons or "year_variant" in reasons


def test_build_password_candidates_file(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "loot_manifest.json").write_text(
        """{
  "parsed_credentials": [
    {
      "username": "svc_recovery",
      "password": "Em3rg3ncyPa$$2025",
      "confidence": "medium",
      "source_file": "Logs/trace.log"
    }
  ]
}""",
        encoding="utf-8",
    )
    (ws / "credentials.json").write_text(
        """{
  "credentials": [
    {
      "username": "svc_recovery",
      "secret": "Em3rg3ncyPa$$2026",
      "status": "valid"
    }
  ]
}""",
        encoding="utf-8",
    )
    path = build_password_candidates_file(ws)
    data = __import__("json").loads(path.read_text(encoding="utf-8"))
    assert data["candidate_count"] >= 2
    verified = [c for c in data["candidates"] if c.get("verified")]
    assert any(c["password"] == "Em3rg3ncyPa$$2026" for c in verified)
