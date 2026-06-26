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


def set_no_color(enabled: bool) -> None:
    console.no_color = enabled


def print_success(message: str) -> None:
    console.print(f"[bold green][+][/bold green] {message}")


def print_warning(message: str) -> None:
    console.print(f"[bold yellow][!][/bold yellow] {message}")


def print_error(message: str) -> None:
    console.print(f"[bold red][-][/bold red] {message}")


def print_info(message: str) -> None:
    console.print(f"[bold cyan][*][/bold cyan] {message}")


def print_scan_line(
    protocol: str,
    ip: str,
    message: str,
    *,
    level: str = "info",
) -> None:
    """Format columnar scan line: [TIMESTAMP] PROTOCOL IP PREFIX MESSAGE."""
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if level == "success":
        prefix = "[bold green][+][/bold green]"
    elif level == "warning":
        prefix = "[bold yellow][!][/bold yellow]"
    elif level == "error":
        prefix = "[bold red][-][/bold red]"
    else:
        prefix = "[bold cyan][*][/bold cyan]"

    proto_str = f"{protocol[:8]:<8}"
    ip_str = f"{ip[:15]:<15}"
    
    console.print(f"[dim]{timestamp}[/dim] {proto_str} {ip_str} {prefix} {message}")


def print_loot_box(title: str, data: dict[str, str]) -> None:
    """Render a clean, Nuclei-inspired panel for critical findings/loot."""
    body = []
    max_key_len = max(len(k) for k in data.keys()) if data else 0
    for k, v in data.items():
        padded_key = f"{k:<{max_key_len}}"
        body.append(f"[bold cyan]{padded_key}[/bold cyan] : [bold white]{v}[/bold white]")
    
    panel_content = "\n".join(body)
    panel = Panel(
        panel_content,
        title=f"[bold yellow][!] {title.upper()}[/bold yellow]",
        border_style="yellow",
        expand=False,
        padding=(0, 2),
    )
    console.print(panel)


def print_section(title: str) -> None:
    """Print a clean horizontal section divider line with a title."""
    divider_len = max(10, 110 - len(title))
    console.print(f"\n[bold dim]───[ {title.upper()} ]" + "─" * divider_len)


def print_table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    from admapper.support.verbosity import is_compact

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
        print_info(f"POST-EX: {len(rows)} opportunity(ies) — details in right panel")
        return
    if title in {"Engagement", "Domain controller"}:
        return
    if rows:
        print_info(f"{title}: {len(rows)} row(s)")


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
        print_info(f"[admapper] auto: {message}")
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
    return answer in {"y", "yes", "s"}
