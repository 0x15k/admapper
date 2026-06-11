import json
from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.engage.auto import (
    _pick_wired_next,
    auto_set_pivot,
    finalize_auto,
    prepare_auto,
    run_auto_exec,
    run_auto_postex_scan,
    sync_owned_from_intel,
)
from admapper.models.workspace import OperationMode


def _session(tmp_path: Path, *, owned: list[str] | None = None) -> Session:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("logging.htb")
    if owned:
        session.workspace.owned_users = list(owned)
    session.persist_workspace()
    return session


def test_sync_owned_marks_msa_health_from_exploit_log(tmp_path: Path) -> None:
    session = _session(tmp_path, owned=["wallace.everette"])
    ws_path = tmp_path / "ws" / "lab"
    (ws_path / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {"account": "msa_health$", "nthash": "a" * 32},
                ],
                "new_users": ["jaylee.clifton"],
            }
        ),
        encoding="utf-8",
    )

    marked = sync_owned_from_intel(session)

    assert "msa_health$" in marked
    assert "jaylee.clifton" in marked
    assert "msa_health$" in session.workspace.owned_users
    assert "jaylee.clifton" in session.workspace.owned_users


def test_auto_set_pivot_prefers_machine_over_human(tmp_path: Path) -> None:
    session = _session(tmp_path, owned=["wallace.everette", "msa_health$"])
    ws_path = tmp_path / "ws" / "lab"
    (ws_path / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {"account": "msa_health$", "nthash": "b" * 32},
                ],
            }
        ),
        encoding="utf-8",
    )

    pivot = auto_set_pivot(session)

    assert pivot == "msa_health$"
    assert session.workspace.pivot_user == "msa_health$"


def test_auto_set_pivot_prefers_post_machine_human(tmp_path: Path) -> None:
    session = _session(
        tmp_path,
        owned=["wallace.everette", "svc_recovery", "msa_health$", "jaylee.clifton"],
    )
    ws_path = tmp_path / "ws" / "lab"
    (ws_path / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {"account": "msa_health$", "nthash": "b" * 32},
                ],
            }
        ),
        encoding="utf-8",
    )

    pivot = auto_set_pivot(session)

    assert pivot == "jaylee.clifton"
    assert session.workspace.pivot_user == "jaylee.clifton"


def test_prepare_finalize_minimal_workspace(tmp_path: Path) -> None:
    session = _session(tmp_path, owned=["wallace.everette"])
    ws_path = tmp_path / "ws" / "lab"
    (ws_path / "auth_inventory.json").write_text(
        json.dumps({"users": [], "computers": []}),
        encoding="utf-8",
    )

    with (
        patch("admapper.engage.auto.run_auto_postex_scan", return_value=False),
        patch("admapper.engage.auto.run_auto_exec", return_value=0),
        patch("admapper.core.verbosity.print_phase"),
        patch("admapper.adcs.enrich.enrich_adcs_findings_file"),
    ):
        prepare_auto(session)
        finalize_auto(session)

    assert session.workspace.mode == OperationMode.AUTO
    assert (ws_path / "escalate.json").is_file()


def test_run_auto_postex_scan_calls_analysis_once(tmp_path: Path) -> None:
    session = _session(tmp_path, owned=["msa_health$"])
    ws_path = tmp_path / "ws" / "lab"
    (ws_path / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {"account": "msa_health$", "nthash": "7fdad697aa96c287e6d33381c3755b17"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (ws_path / "auth_inventory.json").write_text(
        json.dumps({"users": [], "computers": []}),
        encoding="utf-8",
    )

    with (
        patch("admapper.postex.remote_scan.run_remote_task_hijack_scan") as mock_scan,
        patch("admapper.postex.analyze.run_postex_analysis") as mock_analysis,
        patch("admapper.core.provenance.print_step"),
    ):
        assert run_auto_postex_scan(session) is True

    mock_scan.assert_called_once()
    mock_analysis.assert_called_once()


def test_finalize_auto_skips_postex_rescan(tmp_path: Path) -> None:
    session = _session(tmp_path, owned=["wallace.everette"])
    ws_path = tmp_path / "ws" / "lab"
    (ws_path / "auth_inventory.json").write_text(
        json.dumps({"users": [], "computers": []}),
        encoding="utf-8",
    )

    with (
        patch("admapper.engage.auto.run_auto_postex_scan") as mock_postex,
        patch("admapper.engage.auto.run_auto_exec", return_value=0),
        patch("admapper.core.verbosity.print_phase"),
        patch("admapper.adcs.enrich.enrich_adcs_findings_file"),
    ):
        finalize_auto(session)

    mock_postex.assert_not_called()


def test_resolve_pivot_upgrades_stale_machine_pivot(tmp_path: Path) -> None:
    from admapper.core.config import GlobalConfig
    from admapper.core.session import Session
    from admapper.core.workspace import WorkspaceManager
    from admapper.escalate.analyze import resolve_pivot_user

    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.workspace.owned_users = ["msa_health$", "jaylee.clifton"]
    session.workspace.pivot_user = "msa_health$"
    session.persist_workspace()

    assert resolve_pivot_user(session) == "jaylee.clifton"


def test_pick_wired_next_skips_acl_prefers_postex() -> None:
    state = {
        "edges": [
            {
                "module": "acls",
                "technique": "genericwrite",
                "target": "msa_health",
                "ready": True,
                "target_owned": False,
            },
            {
                "module": "postex",
                "technique": "dll_hijack_scheduled_task",
                "target": "jaylee.clifton",
                "ready": True,
                "target_owned": False,
                "op_id": "postex-001",
            },
        ],
    }
    edge = _pick_wired_next(state)
    assert edge is not None
    assert edge["technique"] == "dll_hijack_scheduled_task"
