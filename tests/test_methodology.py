from pathlib import Path

from admapper.report.methodology import methodology_lines


def test_methodology_shows_phases(tmp_path: Path) -> None:
    ws = tmp_path
    (ws / "unauth_scan.json").write_text(
        '{"hosts":[{"address":"10.0.0.1"}],"findings":[]}', encoding="utf-8"
    )
    (ws / "auth_inventory.json").write_text(
        '{"users":[{}],"groups":[],"computers":[],"delegations":[]}',
        encoding="utf-8",
    )
    lines = methodology_lines(ws)
    text = "\n".join(lines)
    assert "AD CHAIN" in text
    assert "OPERATIONAL PROGRESS" in text
