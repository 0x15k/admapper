from admapper.postex.evil_winrm_output import extract_winrm_command_body, strip_evil_winrm_output


def test_extract_winrm_body_keeps_monitor_after_banner() -> None:
    raw = """
Evil-WinRM shell v3.9
Warning: Remote path completions is disabled
No payload found locally: C:\\ProgramData\\VendorApp\\payload.zip.
EXAMPLE\\test.user loaded payload.dll
"""
    out = extract_winrm_command_body(raw)
    assert "payload.zip" in out
    assert "test.user" in out


def test_strip_evil_winrm_keeps_schtasks_blocks() -> None:
    raw = """
Evil-WinRM shell v3.9
 
Warning: Remote path completions is disabled
Folder: \\
TaskName:                             \\VendorApp\\Maintenance Task
Task To Run:                          C:\\App.exe -check C:\\ProgramData\\Network\\payload.zip
Run As User:                          EXAMPLE\\test.user
"""
    out = strip_evil_winrm_output(raw)
    assert "Evil-WinRM" not in out
    assert "Maintenance Task" in out
    assert "test.user" in out
    assert "|" in out
