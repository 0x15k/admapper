from __future__ import annotations

import json
from pathlib import Path

from admapper.report.engagement_map import loot_clue_rows


def test_loot_clue_shows_file_string_not_verified_secret(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "loot_manifest.json").write_text(
        json.dumps(
            {
                "parsed_credentials": [
                    {
                        "username": "svc_sql",
                        "password": "WelcomePassword123!",
                        "source_file": "Logs/trace.log",
                        "confidence": "medium",
                    }
                ]
            }
        )
    )
    (ws / "credentials.json").write_text(
        json.dumps(
            {
                "credentials": [
                    {
                        "username": "svc_sql",
                        "secret": "WelcomePassword123!",
                        "status": "valid",
                    }
                ]
            }
        )
    )
    clues = loot_clue_rows(ws)
    assert len(clues) == 1
    assert clues[0]["string"] == "WelcomePassword123!"
    assert clues[0]["verify_state"] == "verified"
