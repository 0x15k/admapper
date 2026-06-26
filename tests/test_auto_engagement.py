import json
from pathlib import Path
from unittest.mock import patch

import pytest

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
    session.set_domain("target.example")
    if owned:
        session.workspace.owned_users = list(owned)
    session.persist_workspace()
    return session


def test_sync_owned_marks_msa_target_from_exploit_log(tmp_path: Path) -> None:
    session = _session(tmp_path, owned=["target.user"])
    ws_path = tmp_path / "ws" / "lab"
    (ws_path / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {"account": "msa_target$", "nthash": "a" * 32},
                ],
                "new_users": ["target.admin"],
            }
        ),
        encoding="utf-8",
    )

    marked = sync_owned_from_intel(session)

    assert "msa_target$" in marked
    assert "target.admin" in marked
    assert "msa_target$" in session.workspace.owned_users
    assert "target.admin" in session.workspace.owned_users


def test_auto_set_pivot_prefers_machine_over_human(tmp_path: Path) -> None:
    session = _session(tmp_path, owned=["target.user", "msa_target$"])
    ws_path = tmp_path / "ws" / "lab"
    (ws_path / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {"account": "msa_target$", "nthash": "b" * 32},
                ],
            }
        ),
        encoding="utf-8",
    )

    pivot = auto_set_pivot(session)

    assert pivot == "msa_target$"
    assert session.workspace.pivot_user == "msa_target$"


def test_auto_set_pivot_prefers_post_machine_human(tmp_path: Path) -> None:
    session = _session(
        tmp_path,
        owned=["target.user", "svc_user", "msa_target$", "target.admin"],
    )
    ws_path = tmp_path / "ws" / "lab"
    (ws_path / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {"account": "msa_target$", "nthash": "b" * 32},
                ],
            }
        ),
        encoding="utf-8",
    )

    pivot = auto_set_pivot(session)

    assert pivot == "target.admin"
    assert session.workspace.pivot_user == "target.admin"


def test_prepare_finalize_minimal_workspace(tmp_path: Path) -> None:
    session = _session(tmp_path, owned=["target.user"])
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
    session = _session(tmp_path, owned=["msa_target$"])
    ws_path = tmp_path / "ws" / "lab"
    (ws_path / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {"account": "msa_target$", "nthash": "7fdad697aa96c287e6d33381c3755b17"},
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
        patch("admapper.engage.auto.require_target_reachable", return_value="192.168.10.182"),
        patch("admapper.postex.remote_scan.run_remote_task_hijack_scan") as mock_scan,
        patch("admapper.postex.analyze.run_postex_analysis") as mock_analysis,
        patch("admapper.core.provenance.print_step"),
    ):
        assert run_auto_postex_scan(session) is True

    mock_scan.assert_called_once()
    mock_analysis.assert_called_once()


def test_finalize_auto_skips_postex_rescan(tmp_path: Path) -> None:
    session = _session(tmp_path, owned=["target.user"])
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
    session.workspace.owned_users = ["msa_target$", "target.admin"]
    session.workspace.pivot_user = "msa_target$"
    session.persist_workspace()

    assert resolve_pivot_user(session) == "target.admin"


def test_pick_wired_next_skips_acl_prefers_postex() -> None:
    state = {
        "edges": [
            {
                "module": "acls",
                "technique": "genericwrite",
                "target": "msa_target",
                "ready": True,
                "target_owned": False,
            },
            {
                "module": "postex",
                "technique": "dll_hijack_scheduled_task",
                "target": "target.admin",
                "ready": True,
                "target_owned": False,
                "op_id": "postex-001",
            },
        ],
    }
    edge = _pick_wired_next(state)
    assert edge is not None
    assert edge["technique"] == "dll_hijack_scheduled_task"


def test_run_auto_postex_scan_aborts_when_target_unreachable(tmp_path: Path) -> None:
    from admapper.core.connectivity import TargetUnreachableError

    session = _session(tmp_path, owned=["msa_target$"])
    ws_path = tmp_path / "ws" / "lab"
    session.workspace.hosts = "192.168.10.182"
    session.persist_workspace()
    (ws_path / "exploit_log.json").write_text(
        json.dumps({"new_hashes": [{"account": "msa_target$", "nthash": "a" * 32}]}),
        encoding="utf-8",
    )

    with (
        patch(
            "admapper.engage.auto.require_target_reachable",
            side_effect=TargetUnreachableError("192.168.10.182", "[Errno 113] No route to host"),
        ),
        patch("admapper.postex.remote_scan.run_remote_task_hijack_scan") as mock_scan,
        patch("admapper.engage.auto.print_error") as mock_err,
    ):
        assert run_auto_postex_scan(session) is False

    mock_scan.assert_not_called()
    mock_err.assert_called_once()


def test_run_auto_exec_aborts_before_deploy_when_unreachable(tmp_path: Path) -> None:
    session = _session(tmp_path, owned=["target.admin"])
    session.workspace.mode = OperationMode.AUTO
    session.workspace.hosts = "192.168.10.182"
    session.persist_workspace()
    ws_path = tmp_path / "ws" / "lab"
    (ws_path / "escalate.json").write_text(
        json.dumps(
            {
                "edges": [
                    {
                        "module": "wsus",
                        "technique": "wsus_cert_chain",
                        "target": "192.168.10.182",
                        "ready": True,
                        "target_owned": False,
                        "op_id": "wsus-004",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    from admapper.core.connectivity import TargetUnreachableError

    with (
        patch("admapper.engage.auto.run_escalate_analysis"),
        patch("admapper.engage.auto.require_target_reachable", side_effect=TargetUnreachableError("192.168.10.182", "[Errno 113] No route to host")),
        patch("admapper.engage.auto.run_escalate_exec") as mock_exec,
        patch("admapper.engage.auto.print_error"),
        patch("admapper.core.provenance.print_step"),
    ):
        steps = run_auto_exec(session)

    assert steps == 0
    mock_exec.assert_not_called()


def test_finalize_auto_aborts_when_target_unreachable(tmp_path: Path) -> None:
    from admapper.core.connectivity import TargetUnreachableError

    session = _session(tmp_path, owned=["target.user"])
    ws_path = tmp_path / "ws" / "lab"
    session.workspace.hosts = "192.168.10.182"
    session.persist_workspace()
    (ws_path / "auth_inventory.json").write_text(
        json.dumps({"users": [], "computers": []}),
        encoding="utf-8",
    )

    with (
        patch(
            "admapper.engage.auto.require_target_reachable",
            side_effect=TargetUnreachableError("192.168.10.182", "[Errno 113] No route to host"),
        ),
        patch("admapper.engage.auto.run_auto_exec") as mock_exec,
        patch("admapper.engage.auto.run_escalate_analysis") as mock_analysis,
        patch("admapper.engage.auto.print_error") as mock_err,
    ):
        finalize_auto(session)

    mock_exec.assert_not_called()
    mock_analysis.assert_called_once()
    mock_err.assert_called_once()
    assert "unreachable" in str(mock_err.call_args)


def test_deploy_dll_hijack_aborts_before_payload_build(tmp_path: Path) -> None:
    from admapper.core.connectivity import TargetUnreachableError

    session = _session(tmp_path, owned=["msa_target$"])
    session.workspace.mode = OperationMode.AUTO
    session.workspace.hosts = "192.168.10.182"
    session.persist_workspace()
    ws_path = tmp_path / "ws" / "lab"
    (ws_path / "postex_scan.json").write_text(
        json.dumps(
            {
                "dc_ip": "192.168.10.182",
                "shell_user": "msa_target$",
                "findings": [
                    {
                        "drop_path": r"C:\ProgramData\VendorApp",
                        "payload_zip": "payload.zip",
                        "payload_dll": "payload.dll",
                        "task_name": "UpdateChecker Agent",
                        "run_as_user": "target.admin",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    from admapper.postex.deploy import deploy_dll_hijack

    with (
        patch(
            "admapper.postex.deploy.require_target_reachable",
            side_effect=TargetUnreachableError("192.168.10.182", "[Errno 113] No route to host"),
        ),
        patch("admapper.postex.deploy.prepare_hijack_payload") as mock_build,
        patch("admapper.postex.deploy.resolve_winrm_cred"),
    ):
        with pytest.raises(RuntimeError, match="unreachable"):
            deploy_dll_hijack(session)

    mock_build.assert_not_called()
