from __future__ import annotations

from enum import StrEnum

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console(highlight=False)


class ConfirmLevel(StrEnum):
    SAFE = "safe"
    WARN = "warn"
    DANGER = "danger"


_LEVEL_STYLE = {
    ConfirmLevel.SAFE: "green",
    ConfirmLevel.WARN: "yellow",
    ConfirmLevel.DANGER: "bold red",
}


def print_banner(title: str, subtitle: str = "") -> None:
    body = Text(title, style="bold cyan")
    if subtitle:
        body.append("\n")
        body.append(subtitle, style="dim")
    console.print(Panel(body, border_style="cyan", padding=(0, 1)))


def print_success(message: str) -> None:
    console.print(f"[green]✓[/green] {message}")


def print_warning(message: str) -> None:
    console.print(f"[yellow]![/yellow] {message}")


def print_error(message: str) -> None:
    console.print(f"[red]✗[/red] {message}")


def print_info(message: str) -> None:
    console.print(f"[dim]→[/dim] {message}")


def print_table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    from admapper.core.verbosity import is_compact

    if is_compact():
        _print_table_compact(title, columns, rows)
        return
    table = Table(title=title, show_header=True, header_style="bold")
    for column in columns:
        table.add_column(column)
    for row in rows:
        table.add_row(*row)
    console.print(table)


def _print_table_compact(title: str, columns: list[str], rows: list[list[str]]) -> None:
    title_l = title.lower()
    if title == "Auth checks" and len(columns) >= 2:
        parts = {str(r[0]): str(r[1]) for r in rows if len(r) >= 2}
        print_info(
            "Auth: "
            + " · ".join(f"{k}={v}" for k, v in parts.items())
        )
        return
    if "post-exploitation" in title_l or "post-exploitation" in title_l.replace("_", "-"):
        print_info(f"POST-EX: {len(rows)} oportunidad(es) — detalle en panel derecho")
        return
    if title in {"Engagement", "Domain controller"}:
        return
    if rows:
        print_info(f"{title}: {len(rows)} fila(s)")


def confirm(
    message: str,
    *,
    level: ConfirmLevel = ConfirmLevel.SAFE,
    default: bool = False,
    mode_auto: bool = False,
    mode_manual: bool = False,
) -> bool:
    """Prompt operator before noisy or high-impact actions.

    - auto: safe and warn proceed without prompt; danger still prompts.
    - manual: always prompt.
    - semi (default): safe auto-accept; warn/danger prompt.
    """
    if mode_auto and level in (ConfirmLevel.SAFE, ConfirmLevel.WARN):
        print_info(f"[admapper] automático: {message}")
        return True
    if mode_manual:
        pass
    elif level == ConfirmLevel.SAFE:
        print_info(message)
        return True

    style = _LEVEL_STYLE[level]
    suffix = " [Y/n]" if default else " [y/N]"
    console.print(Text(f"{message}{suffix}", style=style))
    answer = console.input("").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes", "s", "si", "sí"}
