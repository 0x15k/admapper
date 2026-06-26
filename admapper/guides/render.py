from __future__ import annotations

from typing import TYPE_CHECKING

from rich.panel import Panel

from admapper.guides.catalog import ManualGuide, get_manual_guide
from admapper.guides.context import GuideContext, build_guide_context, contextualize_text
from admapper.support.output import console, print_table, print_warning
from admapper.support.verbosity import is_verbose

if TYPE_CHECKING:
    from admapper.support.session import Session


def _format_guide(guide: ManualGuide, ctx: GuideContext) -> str:
    lines: list[str] = []
    lines.append(f"[bold]{guide.title}[/bold]")
    lines.append(contextualize_text(guide.summary, ctx))
    if guide.mitre_id:
        lines.append(f"[dim]MITRE {guide.mitre_id}[/dim]")
    if guide.prerequisites:
        lines.append("")
        lines.append("[bold cyan]Prerequisites[/bold cyan]")
        for item in guide.prerequisites:
            lines.append(f"  • {contextualize_text(item, ctx)}")
    if guide.manual_steps:
        lines.append("")
        lines.append("[bold cyan]Manual steps[/bold cyan]")
        for idx, step in enumerate(guide.manual_steps, start=1):
            lines.append(f"  {idx}. {contextualize_text(step, ctx)}")
    if guide.commands:
        lines.append("")
        header = (
            "[bold cyan]Commands (this engagement)[/bold cyan]"
            if ctx.is_contextualized
            else "[bold cyan]Commands (replace placeholders)[/bold cyan]"
        )
        lines.append(header)
        for cmd in guide.commands:
            lines.append(f"  [yellow]{contextualize_text(cmd, ctx)}[/yellow]")
    if guide.tools:
        lines.append("")
        lines.append(f"[dim]Tools: {', '.join(guide.tools)}[/dim]")
    if guide.next_steps:
        lines.append("")
        lines.append("[bold green]Next steps in ADMapper[/bold green]")
        for step in guide.next_steps:
            lines.append(f"  → {contextualize_text(step, ctx)}")
    if guide.references:
        lines.append("")
        for ref in guide.references:
            lines.append(f"[dim]{ref}[/dim]")
    return "\n".join(lines)


def print_manual_exploit_table(commands: list[str]) -> None:
    """Show manual command table only in verbose mode."""
    if not is_verbose() or not commands:
        return
    print_table("Manual exploitation", ["command"], [[c] for c in commands])


def print_manual_guide(key: str, *, session: Session | None = None) -> bool:
    """Render BloodHound-style manual exploitation help for one technique."""
    if not is_verbose():
        return False
    guide = get_manual_guide(key)
    if guide is None:
        print_warning(f"no manual guide for: {key}")
        return False
    ctx = build_guide_context(session) if session else GuideContext()
    console.print()
    console.print(
        Panel(
            _format_guide(guide, ctx),
            title="[bold magenta]Manual exploitation[/bold magenta]",
            border_style="magenta",
            padding=(1, 2),
        )
    )
    console.print()
    return True


def print_manual_guides_for_keys(keys: list[str], *, session: Session | None = None) -> None:
    """Show deduplicated guides for a list of technique keys."""
    seen: set[str] = set()
    for key in keys:
        if key in seen:
            continue
        seen.add(key)
        print_manual_guide(key, session=session)
