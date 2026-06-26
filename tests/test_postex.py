import json
from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.workspace import WorkspaceManager
from admapper.models.host import HostRecord
from admapper.postex.analyze import build_postex_opportunities, run_postex_analysis
from admapper.postex.hijack_intel import (
    _intel_from_monitor_lines,
    extract_hijack_intel,
    intel_from_com_tasks,
    parse_schtasks_list_output,
)
from admapper.postex.remote_scan import run_remote_task_hijack_scan
from admapper.postex.runner import parse_shell_username
from admapper.winrm.client import CommandResult
from admapper.postex.loot_intel import LootIntelResult, LootTaskHint
from admapper.postex.task_hijack import analyze_task_hijack
from admapper.postex.templates import apply_postex_templates


def test_build_postex_opportunities_covers_phase14(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    session.workspace.owned_users = ["jsmith"]
    session.persist_workspace()
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[88], is_domain_controller=True)]
    )

    inventory = {
        "computers": [
            {"name": "WS01", "dns_host": "ws01.target.example"},
        ],
        "smb_shares": ["SYSVOL", "NETLOGON"],
    }
    acl_data = {
        "findings": [
            {
                "right": "dcsync",
                "principal": "jsmith",
                "summary": "DCSync on domain",
            }
        ]
    }

    ops = build_postex_opportunities(
        session,
        inventory=inventory,
        acl_data=acl_data,
        paths_data=None,
    )
    techniques = {o.technique for o in ops}
    assert "adminto" in techniques
    assert "sam_dump" in techniques
    assert "lsa_secrets" in techniques
    assert "lsass_dump" in techniques
    assert "dcsync" in techniques
    assert "dpapi" in techniques
    assert "share_loot" in techniques
    assert "rdp_creds" in techniques


def test_run_postex_analysis_writes_playbook(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    session.workspace.owned_users = ["jsmith"]
    session.persist_workspace()

    inv = {
        "computers": [{"name": "WS01", "dns_host": "ws01.target.example"}],
        "smb_shares": ["SYSVOL"],
    }
    (tmp_path / "ws" / "lab" / "auth_inventory.json").write_text(
        json.dumps(inv),
        encoding="utf-8",
    )

    with patch("admapper.postex.analyze.print_manual_guide"):
        result = run_postex_analysis(session)

    assert result.opportunities
    assert (tmp_path / "ws" / "lab" / "postex_ops.json").is_file()


def test_extract_hijack_intel_from_loot_monitor() -> None:
    loot = LootIntelResult(
        task_hints=[LootTaskHint(task_name="Update Agent", source_file="app.log", line="Task [Update Agent] ok")],
        zip_dll_refs=[
            "app.log: No updates locally: C:\\ProgramData\\Vendor\\Settings_Update.zip."
        ],
        dll_hijack_refs=["app.log: Loading settings_update.dll"],
    )
    intel = extract_hijack_intel(
        loot,
        monitor_log="corp\\svc_user loaded settings_update.dll from Settings_Update.zip",
    )
    assert intel is not None
    assert intel.payload_zip == "Settings_Update.zip"
    assert intel.payload_dll == "settings_update.dll"
    assert "Vendor" in intel.drop_path


def test_intel_from_monitor_log_updatemonitor_lines() -> None:
    monitor = (
        "Task [Update Check] checking for updates\n"
        "No updates found locally: C:\\ProgramData\\UpdateMonitor\\Settings_Update.zip.\n"
        "Loading update applier: C:\\ProgramData\\UpdateMonitor\\settings_update.dll\n"
    )
    mz, md, mdrop, mlog = _intel_from_monitor_lines(monitor.splitlines())
    assert mz == "Settings_Update.zip"
    assert md == "settings_update.dll"
    assert "UpdateMonitor" in (mdrop or "")
    intel = extract_hijack_intel(None, monitor_log=monitor)
    assert intel is not None
    assert intel.payload_zip == "Settings_Update.zip"
    assert intel.com_task_filter == "Update Check" or intel.task_name_hint == "Update Check"


def test_parse_shell_username_from_whoami() -> None:
    assert parse_shell_username("corp\\test.user\r\n") == "test.user"
    assert parse_shell_username("whoami\r\ncorp\\test.user") == "test.user"
    assert parse_shell_username("C:\\Users\\jaylee>whoami\r\ncorp\\test.user") == "test.user"


def test_task_hijack_dedupes_loot_hints_and_detects_writable_acl() -> None:
    hints = [
        LootTaskHint(task_name="Update Agent", source_file="Logs/app.log", line=f"line-{i}")
        for i in range(13)
    ]
    loot = LootIntelResult(
        task_hints=hints,
        zip_dll_refs=["Logs/app.log: C:\\ProgramData\\Vendor\\payload.zip"],
        dll_hijack_refs=["Logs/app.log: settings.dll"],
    )
    acl = r"BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)"
    monitor = r"No updates found locally: C:\ProgramData\Vendor\payload.zip."
    com = r"Update Agent|corp\svc_user|C:\Vendor\app.exe|"

    analysis = analyze_task_hijack(
        loot=loot,
        com_task_output=com,
        monitor_log=monitor,
        acl_output=acl,
    )

    assert len(analysis.findings) == 1
    finding = analysis.findings[0]
    assert finding.run_as_user == "svc_user"
    assert finding.writable is True


def test_intel_from_com_tasks_extracts_zip_dll_run_as() -> None:
    com = (
        "Backup Task|SYSTEM|C:\\Windows\\System32\\cmd.exe|\n"
        "Update Check|CORP\\test.user|C:\\Program Files\\Vendor\\Agent.exe|"
        "-check C:\\ProgramData\\Microsoft\\Network\\Settings_Update.zip"
    )
    intel = intel_from_com_tasks(com)
    assert intel is not None
    assert intel.payload_zip == "Settings_Update.zip"
    assert intel.task_name_hint == "Update Check"
    assert "ProgramData" in intel.drop_path

    analysis = analyze_task_hijack(loot=None, com_task_output=com, acl_output="(WD)")
    assert len(analysis.findings) == 1
    assert analysis.findings[0].run_as_user == "test.user"
    assert analysis.findings[0].payload_zip == "Settings_Update.zip"


def test_parse_schtasks_list_output_pipe_format() -> None:
    schtasks = """
Folder: \\
HostName:                             CORP
TaskName:                             \\UpdateMonitor\\Update Check
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          C:\\Program Files\\Vendor\\Agent.exe -check C:\\ProgramData\\Microsoft\\Network\\Settings_Update.zip
Start In:                             N/A
Run As User:                          CORP\\test.user
"""
    pipe = parse_schtasks_list_output(schtasks)
    assert "Update Check" in pipe
    assert "test.user" in pipe
    assert "Settings_Update.zip" in pipe
    intel = intel_from_com_tasks(pipe)
    assert intel is not None
    assert intel.payload_zip == "Settings_Update.zip"


def test_intel_from_com_tasks_subfolder_task_line() -> None:
    """Recursive COM / schtasks emit leaf task name with zip in arguments."""
    com = (
        "Update Check|CORP\\test.user|C:\\Program Files\\Vendor\\Agent.exe|"
        "-check C:\\ProgramData\\Microsoft\\Network\\Settings_Update.zip"
    )
    intel = intel_from_com_tasks(com)
    assert intel is not None
    assert intel.task_name_hint == "Update Check"
    assert intel.payload_zip == "Settings_Update.zip"
    assert "Network" in intel.drop_path


def test_remote_scan_uses_monitor_log_when_com_empty(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    session.persist_workspace()

    monitor = (
        "Task [Update Check] checking for updates\n"
        "No updates found locally: C:\\ProgramData\\Microsoft\\Network\\Settings_Update.zip.\n"
        "CORP\\test.user loaded settings_update.dll"
    )

    class FakeClient:
        def execute(self, script: str, shell: str = "powershell") -> CommandResult:
            if "Get-ChildItem" in script and "monitor.log" in script:
                return CommandResult(stdout="C:\\ProgramData\\Microsoft\\Network\\monitor.log", stderr="", returncode=0, shell=shell)
            if "Get-Content" in script and "monitor.log" in script:
                return CommandResult(stdout=monitor, stderr="", returncode=0, shell=shell)
            if "schtasks" in script:
                return CommandResult(stdout="", stderr="", returncode=0, shell=shell)
            if "Schedule.Service" in script or "Get-ScheduledTask" in script:
                return CommandResult(stdout="", stderr="", returncode=0, shell=shell)
            if "icacls" in script:
                return CommandResult(
                    stdout=r"BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)",
                    stderr="",
                    returncode=0,
                    shell=shell,
                )
            return CommandResult(stdout="", stderr="", returncode=0, shell=shell)

    cred = type("C", (), {"host": "10.0.0.5", "domain": "target.example", "username": "svc", "uses_nthash": True, "nthash": "abc", "password": None})()

    with (
        patch("admapper.postex.remote_scan.resolve_winrm_cred", return_value=cred),
        patch("admapper.postex.remote_scan.winrm_client_for_cred", return_value=FakeClient()),
        patch("admapper.postex.remote_scan.print_step"),
        patch("admapper.postex.remote_scan.print_ok"),
        patch("admapper.postex.remote_scan.print_warn"),
        patch("admapper.postex.remote_scan.print_warning"),
        patch("admapper.postex.remote_scan.print_success"),
        patch("admapper.postex.remote_scan.print_info"),
    ):
        result = run_remote_task_hijack_scan(session)

    assert not any("could not derive drop paths" in e for e in result.errors)
    assert result.output_path is not None
    payload = json.loads(Path(result.output_path).read_text(encoding="utf-8"))
    assert payload.get("hijack_intel", {}).get("payload_zip") == "Settings_Update.zip"
    assert payload.get("com_task_raw") == ""
    assert "Network" in (payload.get("hijack_intel", {}).get("drop_path") or "")


def test_remote_scan_ignores_loot_com_filter(tmp_path: Path) -> None:
    """Loot zip hint must not filter out differently-named scheduled tasks."""
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    session.persist_workspace()
    loot_dir = tmp_path / "ws" / "lab" / "loot" / "Logs"
    loot_dir.mkdir(parents=True)
    (loot_dir / "monitor.log").write_text(
        "No updates: C:\\ProgramData\\Microsoft\\Network\\Settings_Update.zip\n",
        encoding="utf-8",
    )

    com = (
        "Update Check|CORP\\test.user|C:\\Program Files\\Vendor\\Agent.exe|"
        "-check C:\\ProgramData\\Microsoft\\Network\\Settings_Update.zip"
    )

    monitor_remote = (
        "CORP\\test.user loaded settings_update.dll\n"
        "No updates: C:\\ProgramData\\Microsoft\\Network\\Settings_Update.zip"
    )

    class FakeClient:
        def execute(self, script: str, shell: str = "powershell") -> CommandResult:
            if "Get-ChildItem" in script and "monitor.log" in script:
                return CommandResult(stdout="", stderr="", returncode=0, shell=shell)
            if "Get-Content" in script and "monitor.log" in script:
                return CommandResult(stdout=monitor_remote, stderr="", returncode=0, shell=shell)
            if "System32\\Tasks" in script or "Schedule.Service" in script or "schtasks" in script:
                return CommandResult(stdout=com, stderr="", returncode=0, shell=shell)
            if "icacls" in script:
                return CommandResult(stdout="(WD)", stderr="", returncode=0, shell=shell)
            return CommandResult(stdout="", stderr="", returncode=0, shell=shell)

    cred = type(
        "C",
        (),
        {
            "host": "msa_target.target.example",
            "domain": "target.example",
            "username": "msa_target$",
            "uses_nthash": True,
            "nthash": "7fdad697aa96c287e6d33381c3755b17",
            "password": None,
        },
    )()

    with (
        patch("admapper.postex.remote_scan.resolve_winrm_cred", return_value=cred),
        patch("admapper.postex.remote_scan.winrm_client_for_cred", return_value=FakeClient()),
        patch("admapper.postex.remote_scan.print_step"),
        patch("admapper.postex.remote_scan.print_ok"),
        patch("admapper.postex.remote_scan.print_warn"),
        patch("admapper.postex.remote_scan.print_warning"),
        patch("admapper.postex.remote_scan.print_success"),
        patch("admapper.postex.remote_scan.print_info"),
    ):
        result = run_remote_task_hijack_scan(session)

    assert result.analysis.findings
    assert result.analysis.findings[0].run_as_user == "test.user"
    payload = json.loads(Path(result.output_path).read_text(encoding="utf-8"))
    assert payload.get("findings") and payload["findings"][0]["run_as_user"] == "test.user"


def test_analyze_task_hijack_fallback_from_monitor_only() -> None:
    monitor = (
        "No updates found locally: C:\\ProgramData\\Microsoft\\Network\\Settings_Update.zip.\n"
        "CORP\\test.user loaded settings_update.dll"
    )
    loot = LootIntelResult(
        zip_dll_refs=["monitor: Settings_Update.zip"],
        dll_hijack_refs=["settings_update.dll"],
    )
    analysis = analyze_task_hijack(
        loot=loot,
        com_task_output="",
        monitor_log=monitor,
        acl_output="(WD)",
    )
    assert len(analysis.findings) == 1
    assert analysis.findings[0].run_as_user == "test.user"
    assert analysis.findings[0].payload_zip == "Settings_Update.zip"


def test_analysis_from_scan_payload() -> None:
    from admapper.postex.task_hijack import analysis_from_scan_payload

    data = {
        "findings": [
            {
                "task_name": "Update Check",
                "run_as_user": "test.user",
                "executable": r"C:\Program Files\UpdateMonitor\UpdateMonitor.exe",
                "arguments": "",
                "drop_path": r"C:\ProgramData\UpdateMonitor",
                "payload_zip": "Settings_Update.zip",
                "payload_dll": "settings_update.dll",
                "writable": False,
                "target_arch": "x86",
                "evidence": [],
                "severity": "high",
            }
        ]
    }
    analysis = analysis_from_scan_payload(data)
    assert analysis is not None
    assert analysis.findings[0].run_as_user == "test.user"


def test_apply_postex_templates() -> None:
    out = apply_postex_templates(
        "admapper postex deploy --op <id> -w <workspace> --lhost <host>",
        {"id": "postex-010", "workspace": "lab", "host": "10.0.0.1"},
    )
    assert "postex-010" in out
    assert "lab" in out
