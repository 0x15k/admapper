from admapper.postex.nxc_output import strip_nxc_winrm_output


def test_strip_nxc_14_schtasks_multiline() -> None:
    raw = """
WINRM       msa_target.target.example    5985   MSA_TARGET   [*] http://msa_target.target.example:5985/wsman
WINRM       msa_target.target.example    5985   MSA_TARGET   [+] EXAMPLE\\msa_target$:7fda (Pwn3d!)
WINRM       msa_target.target.example    5985   MSA_TARGET   [+] Executed command (schtasks /query /fo LIST /v)
Folder: \\
TaskName:                             \\VendorApp\\Maintenance Task
Task To Run:                          C:\\Program Files\\Vendor\\App.exe -check C:\\ProgramData\\Microsoft\\Network\\payload.zip
Run As User:                          EXAMPLE\\test.user
"""
    out = strip_nxc_winrm_output(raw)
    assert "TaskName:" in out
    assert "test.user" in out
    assert "payload.zip" in out
    assert "(Pwn3d!)" not in out


def test_strip_nxc_keeps_unprefixed_lines() -> None:
    raw = "TaskName: foo\nRun As User: DOMAIN\\user"
    assert strip_nxc_winrm_output(raw) == raw
