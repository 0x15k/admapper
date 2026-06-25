from unittest.mock import patch
from admapper.core.output import (
    print_success,
    print_warning,
    print_error,
    print_info,
    print_scan_line,
    print_loot_box,
    print_section,
    set_no_color,
)


def test_output_prefixes() -> None:
    with patch("admapper.core.output.console.print") as mock_print:
        print_success("Success message")
        mock_print.assert_called_with("[bold green][+][/bold green] Success message")

        print_warning("Warning message")
        mock_print.assert_called_with("[bold yellow][!][/bold yellow] Warning message")

        print_error("Error message")
        mock_print.assert_called_with("[bold red][-][/bold red] Error message")

        print_info("Info message")
        mock_print.assert_called_with("[bold cyan][*][/bold cyan] Info message")


def test_print_scan_line() -> None:
    with patch("admapper.core.output.console.print") as mock_print:
        print_scan_line("LDAP", "10.129.245.130", "Connection established", level="success")
        args = mock_print.call_args[0][0]
        assert "LDAP" in args
        assert "10.129.245.130" in args
        assert "[bold green][+][/bold green]" in args
        assert "Connection established" in args


def test_print_loot_box() -> None:
    with patch("admapper.core.output.console.print") as mock_print:
        print_loot_box("Critical Loot", {"User": "Administrator", "Secret": "P@ss1"})
        args = mock_print.call_args[0][0]
        # Should be a Panel instance
        assert args.title == "[bold yellow][!] CRITICAL LOOT[/bold yellow]"
        assert "User" in args.renderable
        assert "Administrator" in args.renderable


def test_print_section() -> None:
    with patch("admapper.core.output.console.print") as mock_print:
        print_section("Phase 1")
        args = mock_print.call_args[0][0]
        assert "───[ PHASE 1 ]" in args


def test_set_no_color() -> None:
    set_no_color(True)
    from admapper.core.output import console
    assert console.no_color is True
    set_no_color(False)
    assert console.no_color is False
