from __future__ import annotations

from admapper.graph.terminal_filter import TerminalFilter


def test_filter_suppresses_workspace_noise() -> None:
    f = TerminalFilter()
    assert f.process("✓ workspace active: ws") is None
    assert f.process("✓ hosts set: 10.0.0.1") is None
    assert f.process("→ syncing clock with DC 10.0.0.1 …") is None


def test_filter_dedupes_skew_hints() -> None:
    f = TerminalFilter()
    first = f.process("! fix clock skew: sudo sntp -sS 10.0.0.1")
    second = f.process("! fix clock skew: sudo sntp -sS 10.0.0.1")
    assert first is not None
    assert second is None


def test_filter_folds_invalid_then_valid_cred() -> None:
    f = TerminalFilter()
    assert f.process("! credential invalid: corp.local\\svc_sql (abc)") is None
    assert f.process("! credential invalid: corp.local\\svc_sql (def)") is None
    out = f.process("✓ credential valid: corp.local\\svc_sql (ghi)")
    assert out is not None
    assert "Credencial válida" in out


def test_filter_strips_rich_markup() -> None:
    f = TerminalFilter()
    out = f.process("[green]✓[/green] owned marcado: alice")
    assert out == "✓ owned marcado: alice"
