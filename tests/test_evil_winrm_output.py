from admapper.postex.evil_winrm_output import extract_winrm_command_body, strip_evil_winrm_output


def test_extract_winrm_body_keeps_monitor_after_banner() -> None:
    raw = """
Evil-WinRM shell v3.9
Warning: Remote path completions is disabled
No updates found locally: C:\\ProgramData\\UpdateMonitor\\Settings_Update.zip.
LOGGING\\jaylee.doe loaded settings_update.dll
"""
    out = extract_winrm_command_body(raw)
    assert "Settings_Update.zip" in out
    assert "jaylee.doe" in out


def test_strip_evil_winrm_keeps_schtasks_blocks() -> None:
    raw = """
Evil-WinRM shell v3.9

Warning: Remote path completions is disabled
Folder: \\
TaskName:                             \\UpdateMonitor\\Update Check
Task To Run:                          C:\\Agent.exe -check C:\\ProgramData\\Network\\Settings_Update.zip
Run As User:                          LOGGING\\jaylee.doe
"""
    out = strip_evil_winrm_output(raw)
    assert "Evil-WinRM" not in out
    assert "Update Check" in out
    assert "jaylee.doe" in out
    assert "|" in out
