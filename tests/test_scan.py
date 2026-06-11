from admapper.cli.scan import format_hosts_hint
from admapper.core.discovery import default_workspace_name


def test_default_workspace_name_from_ip() -> None:
    assert default_workspace_name("10.129.20.182") == "target-10-129-20-182"


def test_format_hosts_hint() -> None:
    assert format_hosts_hint("10.129.20.182", "dc01.logging.htb") == (
        "→ add to /etc/hosts: 10.129.20.182  dc01.logging.htb"
    )
    assert format_hosts_hint("10.0.0.1", "-") is None
    assert format_hosts_hint("", "dc01.corp.local") is None


def test_scan_summary_import() -> None:
    from admapper.cli.scan import print_scan_summary, scan_engagement

    assert callable(scan_engagement)
    assert callable(print_scan_summary)
