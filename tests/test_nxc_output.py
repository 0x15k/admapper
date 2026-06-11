from admapper.postex.nxc_output import strip_nxc_winrm_output


def test_strip_nxc_14_schtasks_multiline() -> None:
    raw = """
WINRM       msa_health.logging.htb    5985   MSA_HEALTH   [*] http://msa_health.logging.htb:5985/wsman
WINRM       msa_health.logging.htb    5985   MSA_HEALTH   [+] LOGGING\\msa_health$:7fda (Pwn3d!)
WINRM       msa_health.logging.htb    5985   MSA_HEALTH   [+] Executed command (schtasks /query /fo LIST /v)
Folder: \\
TaskName:                             \\UpdateMonitor\\Update Check
Task To Run:                          C:\\Program Files\\Vendor\\Agent.exe -check C:\\ProgramData\\Microsoft\\Network\\Settings_Update.zip
Run As User:                          LOGGING\\jaylee.clifton
"""
    out = strip_nxc_winrm_output(raw)
    assert "TaskName:" in out
    assert "jaylee.clifton" in out
    assert "Settings_Update.zip" in out
    assert "(Pwn3d!)" not in out


def test_strip_nxc_keeps_unprefixed_lines() -> None:
    raw = "TaskName: foo\nRun As User: DOMAIN\\user"
    assert strip_nxc_winrm_output(raw) == raw
