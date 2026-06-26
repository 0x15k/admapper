from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path

from admapper import __version__
from admapper.report.collect import collect_workspace_report
from admapper.report.scenario import (
    build_scenario_report,
    infer_kill_chain_phase,
    resolve_top_actions,
    roast_candidates_line,
)


def _esc(text: str) -> str:
    return html.escape(str(text or ""))


def build_engagement_html(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
) -> str:
    """Minimal HTML engagement report from scenario data + findings table."""
    owned = list(owned_users or [])
    pivot = pivot_user or (owned[-1] if owned else "(none)")
    domain_s = domain or "(no domain)"
    phase = infer_kill_chain_phase(ws_path, owned)
    roast = roast_candidates_line(ws_path)
    top_actions = resolve_top_actions(
        ws_path,
        pivot=pivot,
        owned=owned,
        domain=domain_s if domain else "",
        workspace=workspace,
        limit=3,
    )
    collected = collect_workspace_report(ws_path)
    scenario_text = build_scenario_report(
        ws_path,
        workspace=workspace,
        domain=domain,
        owned_users=owned,
        pivot_user=pivot,
    )

    finding_rows = ""
    for item in collected.items[:40]:
        finding_rows += (
            f"<tr><td>{_esc(item.severity)}</td>"
            f"<td>{_esc(item.category)}</td>"
            f"<td>{_esc(item.title)}</td>"
            f"<td>{_esc(item.detail[:120])}</td></tr>\n"
        )
    if not finding_rows:
        finding_rows = '<tr><td colspan="4"><em>No findings exported yet</em></td></tr>'

    action_items = ""
    for idx, action in enumerate(top_actions, start=1):
        tag = "RECOMENDADO" if idx == 1 else f"#{idx}"
        action_items += f"<li><strong>[{tag}]</strong> <code>{_esc(action.command)}</code></li>\n"

    roast_block = ""
    if roast:
        roast_block = f"<p><strong>Roast candidates:</strong> {_esc(roast)}</p>"

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <title>ADMapper — {_esc(workspace)}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 960px; }}
    h1, h2 {{ color: #1a3a5c; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; }}
    th {{ background: #eef3f8; }}
    pre {{ background: #f4f4f4; padding: 1rem; overflow-x: auto; font-size: 0.85rem; }}
    code {{ background: #f0f0f0; padding: 0.1rem 0.3rem; }}
    .meta {{ color: #555; }}
  </style>
</head>
<body>
  <h1>ADMapper Engagement Report</h1>
  <p class="meta">Generated {datetime.now(UTC).isoformat()} · ADMapper {_esc(__version__)}</p>
  <h2>Session</h2>
  <ul>
    <li><strong>Workspace:</strong> {_esc(workspace)}</li>
    <li><strong>Domain:</strong> {_esc(domain_s)}</li>
    <li><strong>Pivot:</strong> {_esc(pivot)}</li>
    <li><strong>Owned:</strong> {_esc(", ".join(owned) if owned else "(ninguno)")}</li>
    <li><strong>Phase:</strong> {_esc(phase)}</li>
  </ul>
  {roast_block}
  <h2>Recommended actions</h2>
  <ol>
    {action_items}
  </ol>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Detail</th></tr></thead>
    <tbody>
      {finding_rows}
    </tbody>
  </table>
  <h2>Analyst scenario</h2>
  <pre>{_esc(scenario_text)}</pre>
</body>
</html>
"""


def write_engagement_html(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
