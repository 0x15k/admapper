from __future__ import annotations

import json
from pathlib import Path

from admapper.analysis.attack_vector_catalog import WorkspaceContext, _mssql_present
from admapper.models.spray import DomainLockoutPolicy


def _ctx(ws_path: Path) -> WorkspaceContext:
    return WorkspaceContext(
        ws_path=ws_path,
        users=[],
        policy=DomainLockoutPolicy(),
        owned_users=[],
    )


def test_mssql_present_from_inventory(tmp_path: Path) -> None:
    """Regression: readiness must reflect discovered MSSQL instances written to
    mssql_inventory.json (previously it read a nonexistent postex_findings.json)."""
    (tmp_path / "mssql_inventory.json").write_text(
        json.dumps({"instances": [{"host": "sql01", "port": 1433}]}),
        encoding="utf-8",
    )
    assert _mssql_present(_ctx(tmp_path)) is True


def test_mssql_present_from_unauth_port(tmp_path: Path) -> None:
    (tmp_path / "unauth_scan.json").write_text(
        json.dumps({"hosts": [{"open_ports": [445, 1433]}]}),
        encoding="utf-8",
    )
    assert _mssql_present(_ctx(tmp_path)) is True


def test_mssql_absent(tmp_path: Path) -> None:
    (tmp_path / "mssql_inventory.json").write_text(
        json.dumps({"instances": []}), encoding="utf-8"
    )
    assert _mssql_present(_ctx(tmp_path)) is False
