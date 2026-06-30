"""ADMapper Web Dashboard — professional pentest UI (BloodHound-style).

Generates a single-page app with:
- vis-network attack graph (center)
- Real-time scan terminal via SSE (bottom)
- Findings / credentials / attack paths panels (right sidebar)
- Phase progress bar (top)
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from admapper.dashboard.bloodhound_overlay import (
    BLOODHOUND_LEGEND,
    BLOODHOUND_OVERLAY_CSS,
    BLOODHOUND_OVERLAY_JS,
    load_overlay_for_payload,
)
from admapper.dashboard.output_parser import (
    OUTPUT_PARSER_CSS,
    OUTPUT_PARSER_DRAWER,
    OUTPUT_PARSER_JS,
)
from admapper.dashboard.path_playbook import (
    PATH_PLAYBOOK_CSS,
    PATH_PLAYBOOK_JS,
    PATH_PLAYBOOK_PANEL,
    PATHS_PANEL,
    edge_abuse_maps_json,
    edge_catalog_json,
    playbook_maps_json,
)
from admapper.dashboard.cheatsheet_ui import (
    CHEATSHEET_CSS,
    CHEATSHEET_HTML,
    CHEATSHEET_JS,
    CHEATSHEET_VIEW_TOGGLE,
    cheatsheet_data_js,
)
from admapper.dashboard.workspace_vars_bridge import WORKSPACE_VARS_JS
from admapper.dashboard.workspace_ui import (
    WORKSPACE_MODAL_HTML,
    WORKSPACE_UI_CSS,
    WORKSPACE_UI_JS,
)
from admapper.dashboard.sharphound_import import (
    SHARPHOUND_CONTROLS,
    SHARPHOUND_CSS,
    SHARPHOUND_DROPZONE,
    SHARPHOUND_HEAD,
    SHARPHOUND_JS,
    SHARPHOUND_LEGEND,
)


def _esc(text: Any) -> str:
    return html.escape(str(text or ""))


def build_dashboard_html(
    ws_path: Path | None,
    *,
    workspace: str | None,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
    api_mode: bool = False,
) -> str:
    """Return the full HTML dashboard SPA."""
    domain_s = _esc(domain or "")
    workspace_s = _esc(workspace or "workspace")
    pivot_s = _esc(pivot_user or "")
    edge_catalog_js = f"const EDGE_CATALOG_JS = {edge_catalog_json()};"
    playbook_maps_js = f"const PLAYBOOK_MAPS = {playbook_maps_json()};"
    edge_abuse_js = f"const EDGE_ABUSE_CATALOG = {edge_abuse_maps_json()};"
    cheatsheet_catalog_js = cheatsheet_data_js()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ADMapper — {workspace_s}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
{SHARPHOUND_HEAD}
<style>
/* ── Reset & Base Styles ─────────────────────────────────── */
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg-dark:#0d1117;
  --bg-panel:#161b22;
  --bg-card:#21262d;
  --bg-hover:#30363d;
  --border:#30363d;
  --border-light:#484f58;
  --text:#c9d1d9;
  --text-dim:#8b949e;
  --text-muted:#484f58;
  --accent:#58a6ff;
  --accent-glow:#79c0ff;
  --green:#3fb950;
  --orange:#f0883e;
  --red:#f85149;
  --yellow:#d29922;
  --blue:#58a6ff;
  --purple:#bc8cff;
  --cyan:#56d4dd;
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,SF Mono,Menlo,Consolas,Liberation Mono,monospace;
}}
html,body{{height:100%;overflow:hidden;font-family:var(--font);background:var(--bg-dark);color:var(--text)}}
::-webkit-scrollbar{{width:6px}}
::-webkit-scrollbar-track{{background:var(--bg-panel)}}
::-webkit-scrollbar-thumb{{background:var(--bg-hover);border-radius:3px}}

/* ── Layout Structure ────────────────────────────────────── */
.app{{display:flex;flex-direction:column;height:100vh;overflow:hidden}}
.header{{
  display:flex;align-items:center;gap:1.5rem;flex-shrink:0;
  padding:0.6rem 1.25rem;background:var(--bg-panel);border-bottom:1px solid var(--border);
  z-index:10;
}}
.header .logo{{font-weight:700;font-size:1.15rem;color:var(--accent-glow);letter-spacing:-0.01em;display:flex;align-items:center;gap:0.4rem}}
.header .logo i{{color:var(--accent)}}
.header .meta{{color:var(--text-dim);font-size:0.8rem;display:flex;gap:1.25rem;flex:1;flex-wrap:wrap}}
.header .meta span{{display:flex;align-items:center;gap:0.35rem}}
.header .meta strong{{color:var(--text);font-weight:600}}
.header .status{{
  display:flex;align-items:center;gap:0.4rem;font-size:0.75rem;
  padding:0.25rem 0.65rem;border-radius:4px;border:1px solid var(--border);
  background:var(--bg-card);font-weight:500;white-space:nowrap;
}}
.status .dot{{width:7px;height:7px;border-radius:50%;display:inline-block}}

.main{{display:grid;grid-template-columns:1fr 310px;grid-template-rows:1fr;flex:1;min-height:0;overflow:hidden}}
.graph-area{{position:relative;background:var(--bg-dark);overflow:hidden;min-height:350px;flex:1}}
#graph-canvas{{position:absolute;top:0;left:0;right:0;bottom:0}}

/* ── Graph Filters & Controls ────────────────────────────── */
.graph-header-controls{{
  position:absolute;top:0.75rem;left:0.75rem;display:flex;gap:0.5rem;z-index:5;
  background:rgba(22,27,34,0.85);padding:0.35rem;border-radius:6px;border:1px solid var(--border);
  backdrop-filter:blur(4px);
}}
.filter-group{{display:none}}
.graph-controls-group{{display:flex;gap:0.2rem}}
.btn-graph-ctl{{
  background:var(--bg-card);border:1px solid var(--border);color:var(--text);
  padding:0.3rem 0.6rem;border-radius:4px;font-size:0.7rem;font-weight:500;cursor:pointer;
  transition:all 0.15s;display:flex;align-items:center;gap:0.25rem;
}}
.btn-graph-ctl:hover{{background:var(--bg-hover);border-color:var(--border-light)}}
.btn-graph-ctl.active{{background:var(--accent);border-color:var(--accent);color:#fff}}

.legend{{
  position:absolute;bottom:0.75rem;left:0.75rem;
  background:rgba(22,27,34,0.9);border:1px solid var(--border);
  border-radius:6px;font-size:0.65rem;z-index:5;
  backdrop-filter:blur(4px);max-width:calc(100% - 1.5rem);
}}
.legend-toggle{{
  display:flex;align-items:center;gap:0.35rem;width:100%;
  background:transparent;border:none;color:var(--text-dim);
  padding:0.45rem 0.65rem;cursor:pointer;font-size:0.65rem;font-weight:600;
}}
.legend-toggle:hover{{color:var(--text)}}
.legend-toggle i{{transition:transform 0.15s;font-size:0.55rem}}
.legend.collapsed .legend-toggle i{{transform:rotate(-90deg)}}
.legend-body{{
  display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap;
  padding:0 0.65rem 0.5rem;
}}
.legend.collapsed .legend-body{{display:none}}
.legend-item{{display:flex;align-items:center;gap:0.3rem;white-space:nowrap;font-weight:500}}

.graph-empty{{
  position:absolute;inset:0;z-index:4;display:flex;align-items:center;justify-content:center;
  pointer-events:none;
}}
.graph-empty-inner{{
  text-align:center;color:var(--text-dim);max-width:320px;padding:1rem;
}}
.graph-empty-inner i{{font-size:1.75rem;color:var(--text-muted);margin-bottom:0.65rem;display:block}}
.graph-empty-inner p{{font-size:0.78rem;line-height:1.45;margin:0}}
.header .inline-edit{{cursor:pointer}}
.header .inline-edit:hover{{color:var(--accent-glow)}}
.header-inline-input{{
  background:var(--bg-dark);border:1px solid var(--accent);color:var(--text);
  font-size:0.8rem;font-weight:600;padding:0.1rem 0.35rem;border-radius:3px;
  min-width:6rem;max-width:11rem;font-family:inherit;
}}

/* ── Right Sidebar Panel ────────────────────────────────── */
.sidebar{{
  background:var(--bg-panel);border-left:1px solid var(--border);
  overflow-y:auto;display:flex;flex-direction:column;width:310px;
}}
.panel{{
  border-bottom:1px solid var(--border);
  padding:0.75rem 0.85rem;
}}
.panel:last-child{{border-bottom:none}}
.panel-header{{
  font-size:0.7rem;text-transform:uppercase;letter-spacing:0.08em;
  color:var(--text-dim);font-weight:700;margin-bottom:0.55rem;
  display:flex;justify-content:space-between;align-items:center;gap:0.35rem;
}}
.panel-count{{
  background:var(--bg-hover);padding:0.08rem 0.35rem;border-radius:3px;
  font-size:0.6rem;color:var(--text-dim);border:1px solid var(--border);
}}

/* Node details inspector */
.node-detail{{
  background:var(--bg-card);border-radius:6px;padding:0.6rem 0.7rem;
  border:1px solid var(--border);
}}
.node-detail .nd-name{{font-weight:600;font-size:0.85rem;margin-bottom:0.35rem;word-break:break-all}}
.node-detail .nd-type{{font-size:0.62rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.4rem;font-weight:700}}
.node-detail .nd-row{{font-size:0.72rem;color:var(--text-dim);margin-bottom:0.2rem;display:flex;justify-content:space-between}}
.node-detail .nd-row strong{{color:var(--text);font-weight:500;word-break:break-all}}
.node-detail .nd-edges{{margin-top:0.45rem;max-height:100px;overflow-y:auto;border-top:1px solid var(--border);padding-top:0.35rem}}
.node-detail .nd-edge{{font-size:0.65rem;color:var(--text-dim);padding:0.1rem 0;display:flex;justify-content:space-between}}
.nd-empty{{font-size:0.7rem;color:var(--text-muted);font-style:italic}}

/* Pivot identity card */
.pivot-card{{
  background:linear-gradient(135deg,rgba(240,136,62,0.08) 0%,rgba(22,27,34,0.95) 100%);
  border-radius:6px;padding:0.55rem 0.7rem;
  border:1px solid rgba(240,136,62,0.35);
  display:flex;align-items:center;gap:0.6rem;
}}
.pivot-card .avatar{{
  width:28px;height:28px;border-radius:4px;
  background:var(--orange);display:flex;align-items:center;justify-content:center;
  font-weight:700;font-size:0.85rem;color:#0d1117;flex-shrink:0;
}}
.pivot-card .info .name{{font-weight:600;font-size:0.8rem;color:var(--orange)}}
.pivot-card .info .detail{{font-size:0.68rem;color:var(--text-dim)}}

/* Unified Loot Panel */
.loot-item-card{{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:4px;padding:0.5rem 0.6rem;margin-bottom:0.35rem;
}}
.loot-tag{{
  font-size:0.58rem;font-weight:700;padding:0.05rem 0.35rem;border-radius:2px;
  text-transform:uppercase;
}}
.loot-tag.badge-crit{{background:rgba(248,81,73,0.15);color:var(--red);border:1px solid rgba(248,81,73,0.3)}}
.loot-tag.badge-high{{background:rgba(240,136,62,0.15);color:var(--orange);border:1px solid rgba(240,136,62,0.3)}}
.loot-secret-box{{
  background:#0d1117;border:1px solid var(--border);border-radius:4px;
  padding:0.25rem 0.4rem;display:flex;justify-content:space-between;align-items:center;
  cursor:pointer;margin:0.3rem 0;transition:all 0.15s;
}}
.loot-secret-box:hover{{border-color:var(--border-light);background:var(--bg-hover)}}
.loot-secret-box span{{font-family:var(--mono);font-size:0.68rem;color:#fff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;margin-right:0.35rem}}
.copy-icon{{font-size:0.65rem;color:var(--text-muted);transition:color 0.1s}}
.loot-secret-box:hover .copy-icon{{color:var(--text-dim)}}

/* Credentials State Card */
.cred-state-card{{
  background:var(--bg-card);border:1px solid var(--border);border-radius:4px;
  padding:0.5rem 0.6rem;margin-bottom:0.35rem;transition:border-color 0.15s;
}}
.cred-state-card.active-pivot{{
  border-left:3px solid var(--orange);
  background:linear-gradient(90deg,rgba(240,136,62,0.03) 0%,var(--bg-card) 100%);
}}
.priv-badge{{
  font-size:0.58rem;font-weight:700;padding:0.05rem 0.35rem;border-radius:2px;
}}
.priv-badge.priv-da{{background:rgba(248,81,73,0.15);color:var(--red);border:1px solid rgba(248,81,73,0.3)}}
.priv-badge.priv-user{{background:rgba(88,166,255,0.15);color:var(--blue);border:1px solid rgba(88,166,255,0.3)}}
.pth-badge{{
  font-size:0.58rem;font-weight:600;padding:0.05rem 0.25rem;border-radius:2px;
}}
.pth-badge.yes{{background:rgba(63,185,80,0.12);color:var(--green)}}
.pth-badge.no{{background:rgba(139,148,105,0.1);color:var(--text-dim)}}

/* Next Best Action */
.next-action-card{{
  background:var(--bg-card);border:1px solid var(--border);border-radius:6px;
  padding:0.6rem 0.75rem;
}}
.next-action-source{{
  font-size:0.55rem;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;
  color:var(--orange);margin-bottom:0.2rem;
}}
.next-action-headline{{
  font-size:0.72rem;font-weight:600;color:var(--text);margin-bottom:0.25rem;line-height:1.3;
}}
.engagement-strip{{
  margin:0.45rem 0.55rem 0;padding:0.45rem 0.55rem;border-radius:5px;
  background:linear-gradient(135deg,rgba(56,139,253,0.12),rgba(63,185,80,0.08));
  border:1px solid var(--border);
}}
.engagement-strip .es-stage{{font-size:0.7rem;font-weight:700;color:var(--accent-glow)}}
.engagement-strip .es-meta{{font-size:0.62rem;color:var(--text-dim);margin-top:0.15rem;line-height:1.35}}
.engagement-strip .es-hint{{font-size:0.6rem;color:var(--text-muted);margin-top:0.2rem}}
.pivot-card .pivot-note{{font-size:0.6rem;color:var(--yellow);margin-top:0.2rem}}
.pivot-card .pivot-method{{font-size:0.58rem;color:var(--text-dim);margin-top:0.1rem}}
.syntax-code-block{{
  background:#0d1117;border:1px solid var(--border);border-radius:4px;
  padding:0.4rem 0.5rem;font-family:var(--mono);font-size:0.68rem;
  margin-top:0.35rem;display:flex;justify-content:space-between;align-items:center;
  cursor:pointer;transition:border-color 0.1s;
}}
.syntax-code-block:hover{{border-color:var(--border-light)}}
.syntax-code-block span{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-right:0.35rem}}
.syntax-code-block .copy-icon{{color:var(--text-muted)}}
.syntax-code-block:hover .copy-icon{{color:var(--text-dim)}}

/* Post-ex run modal */
.postex-modal-overlay{{
  display:none;position:fixed;inset:0;background:rgba(0,0,0,0.65);z-index:9000;
  align-items:center;justify-content:center;padding:1rem;
}}
.postex-modal-overlay.open{{display:flex}}
.postex-modal{{
  background:var(--bg-card);border:1px solid var(--border);border-radius:8px;
  width:min(420px,100%);padding:0.85rem 1rem;box-shadow:0 8px 32px rgba(0,0,0,0.45);
}}
.postex-modal h3{{margin:0 0 0.65rem;font-size:0.82rem;color:var(--accent-glow)}}
.postex-field{{margin-bottom:0.55rem}}
.postex-field label{{
  display:block;font-size:0.58rem;text-transform:uppercase;letter-spacing:0.05em;
  color:var(--text-muted);margin-bottom:0.2rem;
}}
.postex-field select,.postex-field input{{
  width:100%;background:#0d1117;border:1px solid var(--border);border-radius:4px;
  color:var(--text);font-size:0.72rem;padding:0.35rem 0.45rem;font-family:var(--mono);
}}
.postex-arch-toggle{{display:flex;gap:0.4rem}}
.postex-arch-toggle label{{
  flex:1;text-align:center;padding:0.35rem;border:1px solid var(--border);border-radius:4px;
  font-size:0.68rem;cursor:pointer;color:var(--text-dim);
}}
.postex-arch-toggle input{{display:none}}
.postex-arch-toggle input:checked + span{{
  display:block;
}}
.postex-arch-toggle label:has(input:checked){{
  border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,0.1);
}}
.postex-modal-actions{{display:flex;gap:0.45rem;margin-top:0.75rem;justify-content:flex-end}}
.postex-run-btn{{
  margin-top:0.5rem;width:100%;padding:0.4rem 0.55rem;border-radius:4px;border:none;
  background:linear-gradient(135deg,var(--orange),#c45a00);color:#0d1117;
  font-size:0.68rem;font-weight:700;cursor:pointer;position:relative;z-index:2;
}}
.postex-run-btn:hover{{filter:brightness(1.08)}}
.postex-run-btn:disabled{{opacity:0.45;cursor:not-allowed}}

.shell-input-bar{{display:none !important;background:#0d1117;border-top:1px solid var(--green)}}
.shell-input-bar.active{{display:flex !important}}
.shell-input-bar .shell-prompt{{color:var(--green);font-family:var(--mono);font-size:0.72rem;padding:0 0.35rem}}
.shell-raw-line{{font-family:var(--mono);font-size:0.68rem;color:#c9d1d9;white-space:pre-wrap;margin:0;padding:0;line-height:1.35}}
.term-shell-banner{{
  padding:0.35rem 0.55rem;font-size:0.68rem;color:var(--green);
  border-bottom:1px solid rgba(63,185,80,0.35);background:rgba(63,185,80,0.12);
  font-weight:600;
}}
.terminal-bar.shell-mode .terminal-header .dot{{background:var(--green)!important}}
.terminal-bar.shell-mode #term-header-title{{color:var(--green)}}
.terminal-bar.shell-mode .terminal-output{{
  background:#05080c;border-top:1px solid rgba(63,185,80,0.2);
}}

/* Operational Pipeline progress bar */
.pipeline-track{{
  display:flex;align-items:center;justify-content:space-between;
  margin:0.45rem 0;position:relative;
}}
.pipeline-node{{
  display:flex;flex-direction:column;align-items:center;position:relative;z-index:2;
}}
.pipeline-node .circle{{
  width:20px;height:20px;border-radius:50%;background:var(--bg-card);
  border:2px solid var(--border-light);color:var(--text-dim);font-size:0.65rem;
  font-weight:700;display:flex;align-items:center;justify-content:center;
  cursor:help;transition:all 0.2s;
}}
.pipeline-node.done .circle{{
  background:var(--green);border-color:var(--green);color:#0d1117;
}}
.pipeline-node.active .circle{{
  background:var(--bg-card);border-color:var(--accent);color:var(--accent);
  box-shadow:0 0 8px rgba(88,166,255,0.3);
}}
.pipeline-node.blocked .circle{{
  background:var(--bg-dark);border-color:var(--red);color:var(--red);opacity:0.65;
}}
.pipeline-node .label{{
  font-size:0.52rem;font-weight:600;color:var(--text-muted);margin-top:0.25rem;
  text-transform:uppercase;letter-spacing:0.04em;
}}
.pipeline-node.done .label{{color:var(--text-dim)}}
.pipeline-node.active .label{{color:var(--accent);font-weight:700}}
.pipeline-line{{
  height:2px;flex:1;background:var(--border-light);position:relative;top:-7px;z-index:1;
  margin:0 -2px;
}}
.pipeline-line.done{{background:var(--green)}}

/* Collapsible Findings Accordion */
.accordion-section{{
  border:1px solid var(--border);border-radius:4px;margin-bottom:0.3rem;
  background:var(--bg-card);overflow:hidden;
}}
.accordion-header{{
  padding:0.45rem 0.65rem;font-size:0.7rem;font-weight:600;
  display:flex;justify-content:space-between;align-items:center;cursor:pointer;
  transition:background 0.15s;
}}
.accordion-header:hover{{background:var(--bg-hover)}}
.accordion-header.crit{{border-left:3px solid var(--red);color:var(--red)}}
.accordion-header.high{{border-left:3px solid var(--orange);color:var(--orange)}}
.accordion-header.med{{border-left:3px solid var(--yellow);color:var(--yellow)}}
.accordion-header.info{{border-left:3px solid var(--blue);color:var(--blue)}}
.accordion-header .chevron{{font-size:0.6rem;color:var(--text-muted);transition:transform 0.15s}}
.accordion-section.open .chevron{{transform:rotate(180deg)}}
.accordion-content{{
  display:none;padding:0.45rem 0.65rem;background:#161b22;
  border-top:1px solid var(--border);
}}
.accordion-section.open .accordion-content{{display:block}}
.findings-list{{list-style:none;font-size:0.7rem}}
.findings-list li{{
  padding:0.25rem 0;border-bottom:1px solid rgba(255,255,255,0.03);
  color:var(--text-dim);line-height:1.35;
}}
.findings-list li:last-child{{border-bottom:none}}

/* Actions Redesign (Grouped) */
.action-group-redesign{{
  background:rgba(22,27,34,0.5);border:1px solid var(--border);
  border-radius:6px;padding:0.5rem;margin-bottom:0.45rem;
}}
.action-group-redesign .group-title{{
  font-size:0.6rem;font-weight:700;color:var(--text-dim);
  text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.35rem;
}}
.action-group-redesign .group-buttons{{
  display:grid;grid-template-columns:repeat(2,1fr);gap:0.3rem;
}}
.action-group-redesign .group-buttons .btn{{
  padding:0.3rem 0.4rem;font-size:0.65rem;border-radius:3px;
  background:var(--bg-card);border:1px solid var(--border-light);
  color:var(--text);font-weight:600;cursor:pointer;transition:all 0.15s;
  text-align:center;
}}
.action-group-redesign .group-buttons .btn:hover:not(:disabled){{
  background:var(--bg-hover);border-color:var(--accent);
}}
.action-group-redesign .group-buttons .btn:disabled{{
  opacity:0.25;cursor:help;
}}

/* ── Bottom Terminal Redesign ────────────────────────────── */
.terminal-bar{{
  background:var(--bg-panel);border-top:1px solid var(--border);
  display:flex;flex-direction:column;flex-shrink:0;overflow:hidden;
  transition:height 0.15s;position:relative;min-height:120px;max-height:70vh;
}}
.terminal-bar.maximized{{height:55vh!important}}
.terminal-resize-handle{{
  position:absolute;top:0;left:0;right:0;height:6px;cursor:ns-resize;z-index:3;
}}
.terminal-resize-handle:hover{{background:rgba(88,166,255,0.15)}}
.terminal-bar.collapsed{{height:28px!important}}
.terminal-bar.collapsed .terminal-output,
.terminal-bar.collapsed .input-bar{{display:none}}
.terminal-header{{
  display:flex;justify-content:space-between;align-items:center;
  padding:0.3rem 0.85rem;font-size:0.7rem;color:var(--text-dim);
  border-bottom:1px solid var(--border);flex-shrink:0;cursor:pointer;
}}
.terminal-header:hover{{background:var(--bg-hover)}}
.terminal-header .term-actions{{display:flex;gap:0.4rem}}
.terminal-header .term-actions button{{
  background:none;border:none;color:var(--text-muted);cursor:pointer;
  font-size:0.65rem;padding:0.1rem 0.35rem;border-radius:3px;
}}
.terminal-header .term-actions button:hover{{color:var(--text);background:var(--bg-card)}}
.terminal-output{{
  flex:1;overflow-y:auto;padding:0.5rem 0.85rem;
  font-family:var(--mono);font-size:0.72rem;line-height:1.55;
  background:#0d1117;
}}

/* Semantic log formatting */
.term-line{{
  border-bottom:1px solid rgba(255,255,255,0.02);padding:0.25rem 0;
}}
.line-summary{{
  display:flex;align-items:center;justify-content:space-between;cursor:pointer;
  width:100%;
}}
.term-line.term-warn .kind-icon{{color:var(--yellow)}}
.term-time{{color:var(--text-muted);font-size:0.6rem;margin-right:0.45rem;flex-shrink:0}}
.term-status-running{{color:var(--yellow);display:inline-flex;align-items:center;gap:0.35rem}}
.kind-icon{{font-size:0.65rem;flex-shrink:0}}
.pivot-badge-terminal{{
  background:rgba(240,136,62,0.12);color:var(--orange);border:1px solid rgba(240,136,62,0.25);
  font-size:0.58rem;font-weight:700;padding:0.04rem 0.25rem;border-radius:2px;
  font-family:var(--font);
}}
.line-text{{color:var(--text-dim);flex:1;word-break:break-all}}
.term-cmd .line-text{{color:var(--accent-glow);font-weight:600}}
.term-done .line-text{{color:var(--green)}}
.term-error .line-text{{color:var(--red)}}
.term-phase .line-text{{color:var(--cyan);font-weight:600}}

.expand-trigger{{font-size:0.6rem;color:var(--text-muted);padding:0.1rem 0.25rem}}
.line-summary:hover .expand-trigger{{color:var(--text-dim)}}

.line-raw-collapse{{
  display:none;background:var(--bg-card);border:1px solid var(--border);
  border-radius:4px;padding:0.4rem 0.6rem;margin-top:0.25rem;margin-left:2.5rem;
  overflow-x:auto;
}}
.term-line.expanded .line-raw-collapse{{display:block}}
.term-line.expanded .expand-trigger{{transform:rotate(90deg);color:var(--accent)}}

/* Session divider */
.session-divider{{
  display:flex;align-items:center;justify-content:center;
  margin:0.75rem 0;position:relative;
}}
.session-divider::before{{
  content:'';position:absolute;left:0;right:0;height:1px;background:var(--border);z-index:1;
}}
.session-divider span{{
  background:#0d1117;padding:0 0.75rem;font-size:0.62rem;font-weight:700;
  color:var(--orange);letter-spacing:0.06em;position:relative;z-index:2;
  border:1px solid var(--border);border-radius:999px;
  display:flex;align-items:center;gap:0.35rem;
}}

/* ── Input Bar ───────────────────────────────────────────── */
.input-bar{{
  display:flex;gap:0.45rem;padding:0.4rem 0.85rem;
  border-top:1px solid var(--border);background:var(--bg-panel);flex-shrink:0;
  flex-wrap:wrap;align-items:center;
}}
.input-bar input{{
  background:var(--bg-dark);border:1px solid var(--border);
  color:var(--text);padding:0.3rem 0.5rem;border-radius:4px;
  font-family:var(--mono);font-size:0.72rem;outline:none;min-width:0;
}}
.input-bar input:focus{{border-color:var(--accent)}}
.input-bar input::placeholder{{color:var(--text-muted)}}

/* ── vis-network tooltip custom class ────────────────────── */
.vis-tooltip{{
  background:var(--bg-card)!important;color:var(--text)!important;
  border:1px solid var(--border-light)!important;border-radius:6px!important;
  padding:0.45rem 0.65rem!important;font-size:0.72rem!important;
  font-family:var(--mono)!important;max-width:350px!important;
  box-shadow:0 6px 16px rgba(0,0,0,0.5)!important;
}}
{SHARPHOUND_CSS}
{BLOODHOUND_OVERLAY_CSS}
{PATH_PLAYBOOK_CSS}
{OUTPUT_PARSER_CSS}
{CHEATSHEET_CSS}
{WORKSPACE_UI_CSS}
</style>
</head>
<body>
<div class="app">

  <!-- ── Header ─────────────────────────────────────────── -->
  <div class="header">
    <span class="logo"><i class="fa-solid fa-network-wired"></i> ADMapper</span>
    <div class="meta">
      <span>Workspace: <strong id="h-workspace" class="inline-edit" data-field="workspace" title="Click to rename">{workspace_s or "…"}</strong></span>
      <span>Domain: <strong id="h-domain">{domain_s or "..."}</strong></span>
      <span>DC: <strong id="h-dc" class="inline-edit" data-field="dc" title="Click to edit target IP">...</strong></span>
      <span>Active Pivot: <strong id="h-pivot" style="color:var(--orange)">{pivot_s or "none"}</strong></span>
    </div>
    {CHEATSHEET_VIEW_TOGGLE}
    <div class="status" id="h-status">
      <span class="dot" style="background:var(--green)"></span> Ready
    </div>
  </div>

  <!-- ── Main Area (Graph Canvas + Panels) ──────────────── -->
  <div id="view-ops" class="main">
    <div class="graph-area">
      <!-- Graph header controls and filter bar -->
      <div class="graph-header-controls">
        <div class="graph-controls-group">
          <button class="btn-graph-ctl active" data-graph-filter="highvalue" onclick="setGraphFilter('highvalue')" title="Pivot, owned, DC, high-value only"><i class="fa-solid fa-bullseye"></i> Focus</button>
          <button class="btn-graph-ctl" data-graph-filter="compromised" onclick="setGraphFilter('compromised')" title="Owned identities and creds"><i class="fa-solid fa-user-check"></i> Owned</button>
          <button class="btn-graph-ctl" data-graph-filter="all" onclick="setGraphFilter('all')" title="Full graph + BloodHound layers"><i class="fa-solid fa-diagram-project"></i> All</button>
          <button class="btn-graph-ctl" onclick="relayoutNetwork()" title="Re-run force layout"><i class="fa-solid fa-sitemap"></i> Layout</button>
          <button class="btn-graph-ctl" onclick="graphFit()" title="Fit all elements in view"><i class="fa-solid fa-expand"></i> Fit</button>
          <button class="btn-graph-ctl" onclick="graphZoom(1.25)" title="Zoom in"><i class="fa-solid fa-magnifying-glass-plus"></i></button>
          <button class="btn-graph-ctl" onclick="graphZoom(0.8)" title="Zoom out"><i class="fa-solid fa-magnifying-glass-minus"></i></button>
          <button class="btn-graph-ctl" onclick="refreshState()" title="Reload data state"><i class="fa-solid fa-arrows-rotate"></i> Refresh</button>
          {SHARPHOUND_CONTROLS}
        </div>
      </div>

      <!-- network canvas -->
      <div id="graph-canvas"></div>

      <div class="graph-empty" id="graph-empty" style="display:none">
        <div class="graph-empty-inner">
          <i class="fa-solid fa-crosshairs"></i>
          <p id="graph-empty-msg">Set target IP to begin</p>
        </div>
      </div>

      <!-- SharpHound import drop zone (Feature 1) -->
      {SHARPHOUND_DROPZONE}

      <!-- Per-hop path playbook (Feature 3) -->
      {PATH_PLAYBOOK_PANEL}

      <!-- network legend -->
      <div class="legend collapsed" id="graph-legend">
        <button type="button" class="legend-toggle" onclick="toggleGraphLegend()" title="Toggle legend">
          <i class="fa-solid fa-chevron-down"></i> Legend
        </button>
        <div class="legend-body" id="legend-body">
        <div class="legend-item" style="color:var(--orange)"><i class="fa-solid fa-star"></i> Pivot</div>
        <div class="legend-item" style="color:var(--green)"><i class="fa-solid fa-circle-check"></i> Compromised</div>
        <div class="legend-item" style="color:var(--red)"><i class="fa-solid fa-crown"></i> High Value/DC</div>
        <div class="legend-item" style="color:#ec4899"><i class="fa-solid fa-key"></i> Kerberoastable</div>
        <div class="legend-item" style="color:#a855f7"><i class="fa-solid fa-unlock"></i> AS-REP Roast</div>
        <div class="legend-item" style="color:var(--purple)"><i class="fa-solid fa-users"></i> AD Group</div>
        <div class="legend-item" style="color:var(--indigo)"><i class="fa-solid fa-desktop"></i> Host/Computer</div>
        <div class="legend-item" style="color:var(--cyan)"><i class="fa-solid fa-user-gear"></i> gMSA</div>
        <div class="legend-item" style="color:#94a3b8"><i class="fa-solid fa-user"></i> Standard User</div>
        {SHARPHOUND_LEGEND}
        {BLOODHOUND_LEGEND}
        </div>
      </div>
    </div>

    <!-- Right Sidebar Panel -->
    <div class="sidebar">
      <div class="sb-pane active" id="sb-pane-ops">
      <!-- Engagement context (workspace-aware) -->
      <div class="engagement-strip" id="engagement-strip">
        <div class="es-stage">Loading engagement…</div>
      </div>

      <!-- Pivot Identity -->
      <div class="panel" style="border-left:3px solid var(--orange);">
        <div class="panel-header">Pivot Identity</div>
        <div id="pivot-display">
          <div class="nd-empty">No active pivot established</div>
        </div>
      </div>

      <!-- Unified Loot Panel (Highest Value) -->
      <div class="panel panel-hero" style="border-left:3px solid var(--green);">
        <div class="panel-header">Unified Loot <span class="panel-count" id="loot-count">0</span></div>
        <div id="loot-list" style="max-height:180px;overflow-y:auto;padding-right:2px;">
          <div class="nd-empty">No credentials/hashes captured</div>
        </div>
      </div>

      <!-- Credential State (Click to Pivot) -->
      <div class="panel">
        <div class="panel-header">Credential State <span class="panel-count" id="cred-count">0</span></div>
        <div id="escalation-target-hint" style="display:none;font-size:0.65rem;color:var(--accent);padding:0.15rem 0.35rem 0.35rem;border-bottom:1px solid rgba(255,255,255,0.04);"></div>
        <div id="cred-list" style="max-height:160px;overflow-y:auto;padding-right:2px;">
          <div class="nd-empty">No domain accounts compromised</div>
        </div>
      </div>

      <!-- Next Best Action Suggestions -->
      <div class="panel panel-hero" style="border-left:3px solid var(--accent);">
        <div class="panel-header">Next Best Action</div>
        <div id="next-action-container">
          <div class="nd-empty">Resolving pipeline guidance...</div>
        </div>
      </div>

      <!-- Pipeline Track -->
      <div class="panel">
        <div class="panel-header">Operational Pipeline</div>
        <div class="pipeline-track" id="pipeline-track"></div>
      </div>

      <!-- Actions (Grouped & Validated) -->
      <div class="panel">
        <div class="panel-header">Execution Console</div>
        <div id="action-buttons-redesign"></div>
      </div>

      <!-- Collapsible ranked findings Accordion -->
      <div class="panel">
        <div class="panel-header">Security Findings <span class="panel-count" id="finding-count-redesign">0</span></div>
        <div id="findings-accordion" style="max-height:220px;overflow-y:auto;padding-right:2px;">
          <div class="nd-empty">No findings parsed</div>
        </div>
      </div>

      <!-- Attack paths (Feature 3) -->
      {PATHS_PANEL}

      <!-- Node detail inspector -->
      <div class="panel" id="panel-node-detail" style="display:none;background:var(--bg-card);">
        <div class="panel-header">Selected Object Info</div>
        <div id="node-detail-content"></div>
      </div>
      </div><!-- /sb-pane-ops -->
    </div>
  </div>

  <!-- ── Cheatsheet Workspace View ──────────────────────── -->
  {CHEATSHEET_HTML}

  <!-- ── Bottom Terminal Area ───────────────────────────── -->
  <div class="terminal-bar" id="terminal-bar" style="height:170px">
    <div class="terminal-resize-handle" id="terminal-resize-handle" title="Drag to resize"></div>
    <div class="terminal-header" onclick="toggleTerminal()">
      <span id="term-header-title"><span class="dot" style="background:var(--green)"></span> Terminal logs</span>
      <span style="display:flex;align-items:center;gap:0.6rem">
        <span id="term-status" class="term-status-running" style="font-size:0.65rem">ready</span>
        <span class="term-actions">
          <button onclick="event.stopPropagation();clearTerminal()" title="Clear log display">Clear</button>
          <button onclick="event.stopPropagation();toggleTerminalMax()" title="Maximize terminal" id="btn-term-max">⤢</button>
          <button id="btn-collapse" onclick="event.stopPropagation();toggleTerminal()">_</button>
        </span>
      </span>
    </div>
    <div class="terminal-output" id="terminal"></div>
    <div class="input-bar" id="ops-input-bar">
      <input id="input-ip" placeholder="target subnet / host IP" style="flex:1;max-width:160px"/>
      <button class="btn-graph-ctl" onclick="doDiscovery()" id="btn-scan" style="margin-right:0.6rem;"><i class="fa-solid fa-magnifying-glass"></i> Discovery</button>
      <button class="btn-graph-ctl" onclick="OutputParser.open()" id="btn-parse-output" title="Parse secretsdump / roast / CME output"><i class="fa-solid fa-file-import"></i> Parse output</button>
      <input id="input-user" placeholder="domain user" style="flex:1;max-width:130px"/>
      <input id="input-pass" placeholder="password" type="password" style="flex:1;max-width:130px"/>
      <button class="btn-graph-ctl btn-primary" onclick="doAuth()" id="btn-auth"><i class="fa-solid fa-key"></i> Authenticate</button>
    </div>
    <div class="input-bar shell-input-bar" id="shell-input-bar">
      <span class="shell-prompt">shell&gt;</span>
      <input id="shell-cmd" placeholder="remote command (Enter)" style="flex:1;font-family:var(--mono);font-size:0.72rem" autocomplete="off" spellcheck="false"/>
      <button class="btn-graph-ctl btn-primary" onclick="sendShellLine()" id="btn-shell-send">Send</button>
      <button class="btn-graph-ctl" onclick="detachShell()" id="btn-shell-detach">Detach</button>
    </div>
  </div>

</div>

<div class="postex-modal-overlay" id="postex-modal-overlay" onclick="if(event.target===this)closePostexModal()">
  <div class="postex-modal" role="dialog" aria-labelledby="postex-modal-title">
    <h3 id="postex-modal-title">Establish Reverse Shell</h3>
    <div class="postex-field">
      <label for="postex-op-select">Post-ex op</label>
      <select id="postex-op-select"></select>
    </div>
    <div class="postex-field">
      <label>Payload arch</label>
      <div class="postex-arch-toggle">
        <label><input type="radio" name="postex-arch" value="x86" checked><span>x86</span></label>
        <label><input type="radio" name="postex-arch" value="x64"><span>x64</span></label>
      </div>
    </div>
    <div class="postex-field">
      <label for="postex-lport">Callback port (--lport)</label>
      <input id="postex-lport" type="number" min="1" max="65535" value="443"/>
    </div>
    <div class="postex-field">
      <label for="postex-lhost">Callback IP (--lhost / VPN)</label>
      <input id="postex-lhost" type="text" placeholder="auto-detect from ATTACKER_IP"/>
    </div>
    <div class="postex-modal-actions">
      <button type="button" class="btn-graph-ctl" onclick="closePostexModal()">Cancel</button>
      <button type="button" class="btn-graph-ctl btn-primary" onclick="submitPostexRun()">Deploy &amp; Listen</button>
    </div>
  </div>
</div>

{OUTPUT_PARSER_DRAWER}

<script>
/* ── Global State ─────────────────────────────────────────── */
let state = {{}};
let network = null;
let nodeData = null;
let edgeData = null;
let physicsOn = true;
let opRunning = false;
let selectedNodeId = null;
let graphNodes = [];
let graphEdges = [];
let currentGraphFilter = 'highvalue';
let graphFilterUserSet = false;
let graphStructureKey = '';
let graphDataKey = '';
let currentSessionPivot = '';
let termLastOutput = '';
let termRunningLabel = '';
let shellMode = false;
let shellLport = 0;
let shellAutoAttachAttempted = false;
let staleShellWarned = false;

/* ── Terminal Output Logging ──────────────────────────────── */
const term = document.getElementById('terminal');

function termScrollBottom() {{
  term.scrollTop = term.scrollHeight;
}}

function termSetRunning(label) {{
  termRunningLabel = label || '';
  opRunning = true;
  setButtonsDisabled(true);
  const status = document.getElementById('term-status');
  if (status) {{
    status.className = 'term-status-running';
    status.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ' + escHtml(label || 'running');
  }}
  const hdr = document.getElementById('h-status');
  if (hdr) {{
    hdr.innerHTML = '<span class="dot" style="background:var(--yellow)"></span> Running';
  }}
}}

function termClearRunning(kind) {{
  if (!opRunning && !termRunningLabel) return;
  opRunning = false;
  termRunningLabel = '';
  setButtonsDisabled(false);
  const status = document.getElementById('term-status');
  if (status) {{
    status.className = '';
    status.textContent = kind === 'error' ? 'error' : 'ready';
  }}
  const hdr = document.getElementById('h-status');
  if (hdr) {{
    hdr.innerHTML = '<span class="dot" style="background:' + (kind === 'error' ? 'var(--red)' : 'var(--green)') + '"></span> ' +
      (kind === 'error' ? 'Error' : 'Ready');
  }}
  if (kind !== 'error') setTimeout(refreshState, 400);
}}

function termLogRaw(text) {{
  if (!text) return;
  const el = document.createElement('pre');
  el.className = 'shell-raw-line';
  el.textContent = text;
  term.appendChild(el);
  termLastOutput += text;
  if (termLastOutput.length > 200000) termLastOutput = termLastOutput.slice(-120000);
  termScrollBottom();
  document.getElementById('terminal-bar').classList.remove('collapsed');
}}

function enableShellMode(lport) {{
  shellMode = true;
  shellLport = lport || shellLport || 443;
  // #region agent log
  fetch('http://127.0.0.1:7915/ingest/8066e3f6-99a9-499c-81b7-48c042eebe7c',{{method:'POST',headers:{{'Content-Type':'application/json','X-Debug-Session-Id':'311366'}},body:JSON.stringify({{sessionId:'311366',hypothesisId:'H3',location:'dashboard_html.py:enableShellMode',message:'shell_mode_enabled',data:{{lport:shellLport}},timestamp:Date.now()}})}}).catch(()=>{{}});
  // #endregion
  const opsBar = document.getElementById('ops-input-bar');
  const shellBar = document.getElementById('shell-input-bar');
  const tbar = document.getElementById('terminal-bar');
  if (opsBar) opsBar.style.display = 'none';
  if (shellBar) shellBar.classList.add('active');
  if (tbar) {{
    tbar.classList.add('shell-mode');
    tbar.classList.remove('collapsed');
    if (!tbar.classList.contains('maximized')) toggleTerminalMax();
  }}
  const title = document.getElementById('term-header-title');
  if (title) {{
    title.innerHTML = '<span class="dot" style="background:var(--green)"></span> Interactive reverse shell';
  }}
  const hdr = document.getElementById('term-status');
  if (hdr) {{
    hdr.className = 'term-status-running';
    hdr.innerHTML = '<i class="fa-solid fa-terminal"></i> shell :' + shellLport;
  }}
  let banner = document.getElementById('term-shell-banner');
  if (!banner) {{
    banner = document.createElement('div');
    banner.id = 'term-shell-banner';
    banner.className = 'term-shell-banner';
    term.parentNode.insertBefore(banner, term);
  }}
  banner.textContent = 'Reverse shell active on port ' + shellLport + ' — output above, type commands in the green bar below';
  const inp = document.getElementById('shell-cmd');
  if (inp) inp.focus();
}}

function disableShellMode() {{
  shellMode = false;
  shellAutoAttachAttempted = false;
  const opsBar = document.getElementById('ops-input-bar');
  const shellBar = document.getElementById('shell-input-bar');
  const tbar = document.getElementById('terminal-bar');
  if (opsBar) opsBar.style.display = '';
  if (shellBar) shellBar.classList.remove('active');
  if (tbar) tbar.classList.remove('shell-mode');
  const title = document.getElementById('term-header-title');
  if (title) {{
    title.innerHTML = '<span class="dot" style="background:var(--green)"></span> Terminal logs';
  }}
  const banner = document.getElementById('term-shell-banner');
  if (banner) banner.remove();
  termClearRunning('done');
}}

function attachShell(lport) {{
  lport = lport || shellLport || 443;
  shellLport = lport;
  termLogSemantic('[*] Attaching interactive shell on port ' + lport + ' …', 'log');
  return apiPost('/api/postex/shell/start', {{ lport: lport }}).then(function (r) {{
    return r.json().then(function (data) {{
      if (!r.ok) {{
        termLogSemantic('[!] ' + (data.error || 'shell attach failed'), 'error');
        termClearRunning('error');
        return false;
      }}
      enableShellMode(lport);
      termLogSemantic('[+] Interactive shell attached — type commands below', 'done');
      termClearRunning('done');
      return true;
    }});
  }}).catch(function () {{
    termLogSemantic('[!] shell attach request failed', 'error');
    termClearRunning('error');
    return false;
  }});
}}

function sendShellLine() {{
  const inp = document.getElementById('shell-cmd');
  if (!inp) return;
  const line = inp.value;
  if (!line.trim()) return;
  inp.value = '';
  termLogRaw(line + '\\n');
  apiPost('/api/postex/shell/send', {{ line: line }});
}}

function detachShell() {{
  apiPost('/api/postex/shell/stop', {{}}).then(function () {{
    disableShellMode();
    termLogSemantic('[*] Shell detached', 'phase');
  }});
}}

window.attachShell = attachShell;
window.sendShellLine = sendShellLine;
window.detachShell = detachShell;

function syncShellFromState(s) {{
  const sh = (s || state || {{}}).shell;
  if (!sh || !sh.connected) {{
    if (sh && sh.stale_marker && !opRunning && !staleShellWarned) {{
      staleShellWarned = true;
      termLogSemantic(
        '[!] Previous shell session ended — re-run Establish Reverse Shell to get a new callback',
        'warn'
      );
    }}
    if (!opRunning && shellMode) disableShellMode();
    return;
  }}
  staleShellWarned = false;
  shellLport = sh.lport || shellLport || 443;
  if (sh.attached || shellMode) {{
    if (!shellMode) enableShellMode(shellLport);
    return;
  }}
  if (!opRunning && !shellAutoAttachAttempted) {{
    shellAutoAttachAttempted = true;
    attachShell(shellLport);
  }}
}}

function termLogSemantic(text, kind) {{
  if (!text) return;
  
  const el = document.createElement('div');
  el.className = 'term-line term-' + (kind || 'log');
  
  const now = new Date();
  const ts = String(now.getHours()).padStart(2,'0') + ':' +
             String(now.getMinutes()).padStart(2,'0') + ':' +
             String(now.getSeconds()).padStart(2,'0');
             
  let outputText = text;
  let pivotTag = '';
  
  const pivotMatch = text.match(/\\[pivot:([^\\]]+)\\]/);
  if (pivotMatch) {{
    const pUser = pivotMatch[1];
    pivotTag = `<span class="pivot-badge-terminal">${{escHtml(pUser)}}</span> `;
    outputText = text.replace(/\\[pivot:[^\\]]+\\]/, '').trim();
    
    if (pUser !== currentSessionPivot) {{
      const div = document.createElement('div');
      div.className = 'session-divider';
      div.innerHTML = `<span><i class="fa-solid fa-arrows-spin"></i> pivot session: ${{escHtml(pUser)}}</span>`;
      term.appendChild(div);
      currentSessionPivot = pUser;
    }}
  }}
  
  let icon = 'fa-circle-notch';
  if (kind === 'done') icon = 'fa-circle-check';
  else if (kind === 'error' || kind === 'warn') icon = 'fa-circle-xmark';
  else if (kind === 'phase') icon = 'fa-flag';
  else if (kind === 'cmd') icon = 'fa-terminal';
  
  el.innerHTML = `
    <div class="line-summary" onclick="toggleRawLog(this)">
      <span class="term-time">${{ts}}</span>
      <span style="display:flex;align-items:center;gap:0.35rem;flex:1;">
        <i class="fa-solid ${{icon}} kind-icon"></i>
        ${{pivotTag}}
        <span class="line-text">${{escHtml(outputText)}}</span>
      </span>
      <i class="fa-solid fa-chevron-right expand-trigger" title="View details"></i>
    </div>
    <div class="line-raw-collapse">
      <pre class="mono" style="color:var(--text-dim);font-size:0.65rem;white-space:pre-wrap;">${{escHtml(text)}}</pre>
    </div>
  `;
  
  term.appendChild(el);
  termLastOutput += (termLastOutput ? '\\n' : '') + outputText;
  if (termLastOutput.length > 120000) termLastOutput = termLastOutput.slice(-80000);
  termScrollBottom();
  
  document.getElementById('terminal-bar').classList.remove('collapsed');
  updateStatus(kind);
}}

function toggleRawLog(summaryEl) {{
  const container = summaryEl.parentElement;
  container.classList.toggle('expanded');
}}

function escHtml(s) {{
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}}

function clearTerminal() {{
  term.innerHTML = '';
}}

function toggleTerminalMax() {{
  const tb = document.getElementById('terminal-bar');
  if (!tb) return;
  tb.classList.toggle('maximized');
  const btn = document.getElementById('btn-term-max');
  if (btn) btn.textContent = tb.classList.contains('maximized') ? '⤡' : '⤢';
}}

function initTerminalResize() {{
  const bar = document.getElementById('terminal-bar');
  const handle = document.getElementById('terminal-resize-handle');
  if (!bar || !handle || handle.dataset.bound === '1') return;
  handle.dataset.bound = '1';
  let startY = 0;
  let startH = 0;
  handle.addEventListener('mousedown', function (e) {{
    e.preventDefault();
    startY = e.clientY;
    startH = bar.offsetHeight;
    function onMove(ev) {{
      const next = Math.min(window.innerHeight * 0.7, Math.max(120, startH + (startY - ev.clientY)));
      bar.style.height = next + 'px';
      bar.classList.remove('maximized');
    }}
    function onUp() {{
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      if (network) network.redraw();
    }}
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }});
}}

function toggleTerminal() {{
  const tb = document.getElementById('terminal-bar');
  tb.classList.toggle('collapsed');
  document.getElementById('btn-collapse').textContent = tb.classList.contains('collapsed') ? '+' : '_';
}}

/* ── Copy to Clipboard Helper ────────────────────────────── */
function copyToClipboard(text, label) {{
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {{
    termLogSemantic('Copied ' + label + ' to clipboard', 'done');
  }}).catch(() => {{
    termLogSemantic('Failed to copy ' + label, 'error');
  }});
}}

/* ── SSE connection ──────────────────────────────────────── */
function connectSSE() {{
  const es = new EventSource('/api/events');
  es.onmessage = (e) => {{
    try {{
      const d = JSON.parse(e.data);
      if (d.type === 'state') {{
        try {{ const inner = JSON.parse(d.line); if (inner.refresh) refreshState(); }} catch {{}}
        return;
      }}
      if (d.type === 'shell_ready') {{
        let meta = {{}};
        try {{ meta = JSON.parse(d.line || '{{}}'); }} catch {{}}
        const lp = meta.lport || 443;
        shellLport = lp;
        if (meta.attached) {{
          enableShellMode(lp);
          termLogSemantic('[+] Interactive shell attached — type commands below', 'done');
          termClearRunning('done');
        }} else if (!opRunning) {{
          attachShell(lp);
        }}
        return;
      }}
      if (d.type === 'shell_stopped') {{
        disableShellMode();
        return;
      }}
      if (d.type === 'shell') {{
        termLogRaw(d.line || '');
        return;
      }}
      termLogSemantic(d.line || '', d.type || 'log');
      updateStatus(d.type);
    }} catch {{}}
  }};
  es.onerror = () => {{
    setTimeout(connectSSE, 3000);
  }};
}}

function updateStatus(kind) {{
  if (kind === 'phase' || kind === 'cmd') {{
    if (!opRunning) termSetRunning(termRunningLabel || 'operation');
    return;
  }}
  if (kind === 'done' || kind === 'error' || kind === 'warn') {{
    if (kind === 'done' || kind === 'error') termClearRunning(kind === 'error' ? 'error' : 'done');
    else if (opRunning) {{
      const status = document.getElementById('term-status');
      if (status && termRunningLabel) {{
        status.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ' + escHtml(termRunningLabel);
      }}
    }}
  }}
}}

function setButtonsDisabled(disabled) {{
  document.querySelectorAll('#action-buttons-redesign .btn, #btn-auth, #btn-scan, #btn-parse-output').forEach(b => {{
    b.disabled = disabled;
  }});
}}

/* ── API Operations ───────────────────────────────────────── */
function apiPost(path, body) {{
  return fetch(path, {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify(body || {{}}),
  }});
}}

function runOp(label, path, body) {{
  termSetRunning(label);
  termLogSemantic('[*] Running: ' + label, 'phase');
  return apiPost(path, body || {{}}).then(function (r) {{
    return r.json().then(function (data) {{
      if (!r.ok) {{
        const msg = data.error || ('HTTP ' + r.status);
        termLogSemantic('[!] ' + msg, r.status === 409 ? 'warn' : 'error');
        termClearRunning(r.status === 409 ? 'warn' : 'error');
        return data;
      }}
      if (r.status !== 202) termClearRunning('done');
      return data;
    }}).catch(function () {{
      if (!r.ok) {{
        termLogSemantic('[!] HTTP ' + r.status, 'error');
        termClearRunning('error');
      }}
      return {{}};
    }});
  }}).catch(function (e) {{
    termLogSemantic('[!] Request failed: ' + e, 'error');
    termClearRunning('error');
    return {{}};
  }});
}}

window.runOp = runOp;
window.termLastOutput = function () {{ return termLastOutput; }};

function hijackPostexOps(s) {{
  const ops = (s && s.postex_ops) || [];
  return ops.filter(function (o) {{ return o.runnable; }});
}}

function openPostexModal(opts) {{
  opts = opts || {{}};
  const overlay = document.getElementById('postex-modal-overlay');
  if (!overlay) return;
  const ops = hijackPostexOps(state);
  const sel = document.getElementById('postex-op-select');
  if (!sel) return;
  sel.innerHTML = '';
  if (!ops.length) {{
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'No DLL hijack ops — run: admapper postex scan';
    sel.appendChild(opt);
  }} else {{
    ops.forEach(function (o) {{
      const opt = document.createElement('option');
      opt.value = o.id;
      opt.textContent = o.id + ' — ' + (o.title || o.technique || 'hijack');
      sel.appendChild(opt);
    }});
  }}
  const prefOp = opts.op || (state.next_action || {{}}).op_id || (ops[0] && ops[0].id) || '';
  if (prefOp) sel.value = prefOp;
  const lhost = document.getElementById('postex-lhost');
  const cv = state.cheatsheet_vars || {{}};
  if (lhost) lhost.value = opts.lhost || cv.LHOST || cv.ATTACKER_IP || '';
  const lport = document.getElementById('postex-lport');
  if (lport) lport.value = String(opts.lport || 443);
  const arch = String(opts.arch || 'x86').toLowerCase();
  const archInput = document.querySelector('input[name="postex-arch"][value="' + arch + '"]');
  if (archInput) archInput.checked = true;
  overlay.classList.add('open');
}}

function closePostexModal() {{
  const overlay = document.getElementById('postex-modal-overlay');
  if (overlay) overlay.classList.remove('open');
}}

function submitPostexRun() {{
  const sel = document.getElementById('postex-op-select');
  const op = sel ? sel.value.trim() : '';
  if (!op) {{
    termLogSemantic('[!] Select a post-ex op (run postex scan first)', 'error');
    return;
  }}
  disableShellMode();
  const archEl = document.querySelector('input[name="postex-arch"]:checked');
  const arch = archEl ? archEl.value : 'x86';
  const lport = parseInt(document.getElementById('postex-lport').value, 10) || 443;
  const lhost = (document.getElementById('postex-lhost') || {{}}).value.trim();
  closePostexModal();
  const ws = (state.meta && state.meta.workspace) ? state.meta.workspace : '';
  runOp('Postex ' + op, '/api/postex/run', {{
    op: op,
    arch: arch,
    lport: lport,
    lhost: lhost || undefined,
    workspace: ws || undefined,
  }});
}}

window.openPostexModal = openPostexModal;
window.closePostexModal = closePostexModal;
window.submitPostexRun = submitPostexRun;

function doDiscovery() {{
  if (typeof WorkspaceVars !== 'undefined') WorkspaceVars.applyTerminalToVars();
  const ip = (typeof WorkspaceVars !== 'undefined' ? WorkspaceVars.get().DC_IP : '') ||
    document.getElementById('input-ip').value.trim();
  if (!ip) {{
    termLogSemantic('[!] Enter DC / target IP in the terminal bar or header', 'error');
    return;
  }}
  if (state.workspace_required) {{
    termLogSemantic('[!] Create or open a workspace first', 'error');
    return;
  }}
  runOp('Discovery ' + ip, '/api/scan', {{ip, DC_IP: ip, host: ip}});
}}

function doAuth() {{
  if (typeof WorkspaceVars !== 'undefined') {{
    WorkspaceVars.applyTerminalToVars();
    const v = WorkspaceVars.get();
    const r = WorkspaceVars.readiness();
    if (!r.auth_ready) {{
      termLogSemantic('[!] Need DC IP, username, and password (or hash in vars)', 'error');
      return;
    }}
    termSetRunning('Authenticate ' + (v.USERNAME || ''));
    termLogSemantic('[*] Running: Authenticate ' + (v.USERNAME || ''), 'phase');
    WorkspaceVars.connectFromTerminal().then(function (data) {{
      if (data && data.error) {{
        termLogSemantic('[!] ' + data.error, 'error');
        termClearRunning('error');
      }}
    }}).catch(function () {{ termClearRunning('error'); }});
    return;
  }}
  const username = document.getElementById('input-user').value.trim();
  const password = document.getElementById('input-pass').value;
  const ip = document.getElementById('input-ip').value.trim();
  if (!username || !password) {{
    termLogSemantic('Please enter username and password credentials', 'error');
    return;
  }}
  const body = {{username, password, workspace_vars: {{USERNAME: username, PASSWORD: password, DC_IP: ip}}}};
  if (ip) body.ip = ip;
  apiPost('/api/workspace/connect', body);
}}

function doExploit() {{ runOp('Exploit chain', '/api/exploit'); }}
function doAcls() {{ runOp('ACL analysis', '/api/acls'); }}
function doEnum() {{
  runOp('Enumerate users', '/api/enum', {{}});
}}
function doAsrep() {{ runOp('AS-REP roast', '/api/asreproast'); }}
function doKerb() {{ runOp('Kerberoast', '/api/kerberoast'); }}
function doBrief() {{ runOp('Engagement brief', '/api/brief', {{auto: true}}); }}

function triggerDiscoveryPrompt() {{
  const ip = document.getElementById('input-ip');
  if (ip) {{
    ip.focus();
    termLogSemantic('Enter target IP range and click Discovery', 'log');
  }}
}}

function triggerSprayPrompt() {{
  const pw = prompt('Enter password candidate for spray:');
  if (pw) {{
    apiPost('/api/spray', {{password: pw}});
  }}
}}

function doPivot(username) {{
  apiPost('/api/pivot', {{username}}).then(r => r.json()).then(d => {{
    if (d.state) renderState(d.state);
  }});
}}

/* ── Refresh state and render components ──────────────────── */
async function refreshState() {{
  try {{
    const r = await fetch('/api/state');
    state = await r.json();
    renderState(state);
  }} catch {{}}
}}

function renderState(s) {{
  state = s;
  const meta = s.meta || {{}};
  const wsEl = document.getElementById('h-workspace');
  if (wsEl && !wsEl.querySelector('input')) {{
    wsEl.textContent = meta.workspace || (s.workspace_required ? '…' : '…');
  }}
  document.getElementById('h-domain').textContent = meta.domain && meta.domain !== '???' ? meta.domain : '...';
  const dcEl = document.getElementById('h-dc');
  if (dcEl && !dcEl.querySelector('input')) {{
    dcEl.textContent = meta.dc_host || meta.dc_ip || '...';
  }}
  document.getElementById('h-pivot').textContent = (s.player||{{}}).pivot || 'none';

  if (s.workspace_required) {{
    showWorkspaceModal(true);
  }} else {{
    showWorkspaceModal(false);
  }}
  bindWorkspaceModal();
  bindHeaderInlineEdit();

  renderPivotCard(s);
  renderEngagementStrip(s);
  renderLootPanel(s);
  renderCredentialState(s);
  renderNextBestAction(s);
  renderOperationalPipeline(s);
  renderActionsRedesign(s);
  renderFindingsFeed(s);
  renderGraph(s.graph || {{}});
  if (typeof WorkspaceVars !== 'undefined') WorkspaceVars.syncFromState(s);
  if (typeof PathPlaybook !== 'undefined') PathPlaybook.syncFromState(s);
  if (typeof BloodHoundOverlay !== 'undefined') BloodHoundOverlay.syncFromState(s);
  if (typeof CheatsheetView !== 'undefined') CheatsheetView.syncFromState(s);
  if (typeof WorkspaceVars !== 'undefined') WorkspaceVars.updateReadinessUI();
  syncShellFromState(s);
}}

/* ── Unified Loot Section ─────────────────────────────────── */
function renderLootPanel(s) {{
  const el = document.getElementById('loot-list');
  el.innerHTML = '';
  
  const clues = s.clues || [];
  const pth = s.pth_sessions || [];
  
  const lootItems = [];
  
  clues.forEach(c => {{
    lootItems.push({{
      type: 'password',
      user: c.user,
      secret: c.string,
      source: c.source || 'Loot File',
      severity: 'critical',
      tag: 'Password',
      badgeClass: 'badge-crit'
    }});
  }});
  
  pth.forEach(p => {{
    lootItems.push({{
      type: 'hash',
      user: p.account,
      secret: p.nthash,
      source: p.winrm_cmd || 'PTH viable hash',
      severity: 'high',
      tag: 'NT Hash',
      badgeClass: 'badge-high'
    }});
  }});
  
  // Sort critical (plaintext) first, then high (hashes)
  lootItems.sort((a, b) => {{
    if (a.severity !== b.severity) {{
      return a.severity === 'critical' ? -1 : 1;
    }}
    return a.user.localeCompare(b.user);
  }});
  
  document.getElementById('loot-count').textContent = lootItems.length;
  
  if (lootItems.length === 0) {{
    el.innerHTML = '<div class="nd-empty">No loot acquired yet</div>';
    return;
  }}
  
  lootItems.forEach(item => {{
    const row = document.createElement('div');
    row.className = 'loot-item-card';
    
    let copyText = item.secret;
    let clickTitle = 'Click to copy secret';
    if (item.type === 'hash' && item.source) {{
      copyText = item.source;
      clickTitle = 'Click to copy full WinRM command';
    }}
    
    let extraHash = '';
    if (item.type === 'hash') {{
      const isMachine = item.user.endsWith('$');
      const reuse = isMachine ? 'Machine account context (low reuse outside own system)' : 'High reuse potential (viable for PTH across domain)';
      const targets = isMachine ? item.user.replace('$', '').toUpperCase() + ', DCs' : 'DCs, all domain member servers';
      extraHash = `
        <div style="font-size:0.62rem;color:var(--text-dim);margin-top:0.3rem;display:flex;flex-direction:column;gap:0.15rem;border-top:1px solid rgba(255,255,255,0.03);padding-top:0.25rem;margin-bottom:0.25rem;">
          <div><strong>Status:</strong> <span style="color:var(--orange);font-weight:600;">Uncracked (PTH Viable)</span></div>
          <div><strong>Reuse:</strong> ${{escHtml(reuse)}}</div>
          <div><strong>Targets:</strong> ${{escHtml(targets)}}</div>
        </div>
      `;
    }}
    
    row.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.25rem;">
        <span style="font-weight:600;font-size:0.75rem;color:var(--text);">${{escHtml(item.user)}}</span>
        <span class="loot-tag ${{item.badgeClass}}">${{escHtml(item.tag)}}</span>
      </div>
      <div class="loot-secret-box" data-copy-val="${{escHtml(copyText)}}" data-copy-label="${{item.type === 'hash' ? 'PTH Command' : 'Password'}}" title="${{clickTitle}}">
        <span class="mono">${{escHtml(item.secret)}}</span>
        <i class="fa-regular fa-copy copy-icon"></i>
      </div>
      ${{extraHash}}
      <div style="font-size:0.6rem;color:var(--text-muted);margin-top:0.25rem;text-overflow:ellipsis;overflow:hidden;white-space:nowrap;" title="${{escHtml(item.source)}}">
        Src: ${{escHtml(item.source)}}
      </div>
    `;
    el.appendChild(row);
  }});
}}

/* ── Expanded Credential State ────────────────────────────── */
function renderCredentialState(s) {{
  const el = document.getElementById('cred-list');
  const escHint = document.getElementById('escalation-target-hint');
  el.innerHTML = '';
  const creds = s.creds || [];
  const pth = s.pth_sessions || [];
  
  const escTarget = String(s.escalation_target || '').trim();
  const ownedSet = new Set(((s.player || {{}}).owned || []).map(u => String(u).toLowerCase().replace(/\\$/g, '')));
  if (escHint) {{
    if (escTarget && !ownedSet.has(escTarget.toLowerCase().replace(/\\$/g, ''))) {{
      escHint.style.display = 'block';
      escHint.innerHTML = `Escalation target: <strong>${{escHtml(escTarget)}}</strong> <span style="color:var(--text-muted)">(scheduled task run-as)</span>`;
    }} else {{
      escHint.style.display = 'none';
      escHint.innerHTML = '';
    }}
  }}
  
  const allCreds = [];
  
  creds.forEach(c => {{
    const isDA = c.user.toLowerCase().includes('admin') || c.user.toLowerCase() === 'administrator';
    allCreds.push({{
      user: c.user,
      status: c.status,
      type: 'Password',
      privilege: isDA ? 'Domain Admin' : 'Domain User',
      pth: 'NO',
      unlockedPaths: isDA ? 5 : 2,
      lastUsed: 'Verified recently',
      isPth: false
    }});
  }});
  
  pth.forEach(p => {{
    const isDA = p.account.toLowerCase().includes('admin') || p.account.toLowerCase() === 'administrator' || p.account.endsWith('$');
    allCreds.push({{
      user: p.account,
      status: 'valid',
      type: 'NT Hash',
      privilege: isDA ? 'Domain Admin' : 'Domain User',
      pth: 'YES',
      unlockedPaths: isDA ? 6 : 3,
      lastUsed: 'Acquired recently',
      isPth: true
    }});
  }});
  
  document.getElementById('cred-count').textContent = allCreds.length;
  
  if (allCreds.length === 0) {{
    el.innerHTML = '<div class="nd-empty">No credentials verified</div>';
    return;
  }}
  
  allCreds.forEach(c => {{
    const card = document.createElement('div');
    card.className = 'cred-state-card';
    if (c.user.toLowerCase() === ((s.player || {{}}).pivot || '').toLowerCase()) {{
      card.classList.add('active-pivot');
    }}
    
    const pthBadge = c.pth === 'YES' ? '<span class="pth-badge yes">PTH: YES</span>' : '<span class="pth-badge no">PTH: NO</span>';
    const privClass = c.privilege === 'Domain Admin' ? 'priv-da' : 'priv-user';
    
    let hashExtra = '';
    if (c.type === 'NT Hash') {{
      const isMachine = c.user.endsWith('$');
      const reuse = isMachine ? 'Machine account context (low reuse outside own system)' : 'High reuse potential (viable for PTH across domain)';
      const targets = isMachine ? c.user.replace('$', '').toUpperCase() + ', DCs' : 'DCs, all domain member servers';
      hashExtra = `
        <div style="font-size:0.62rem;color:var(--text-dim);margin-top:0.25rem;border-top:1px solid rgba(255,255,255,0.03);padding-top:0.2rem;display:flex;flex-direction:column;gap:0.1rem;">
          <div><strong>Hash Status:</strong> <span style="color:var(--orange)">Uncracked (PTH Viable)</span></div>
          <div><strong>Reuse:</strong> ${{escHtml(reuse)}}</div>
          <div><strong>Targets:</strong> ${{escHtml(targets)}}</div>
        </div>
      `;
    }}
    
    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.25rem;">
        <span style="font-weight:600;font-size:0.75rem;">${{escHtml(c.user)}}</span>
        <span class="priv-badge ${{privClass}}">${{escHtml(c.privilege)}}</span>
      </div>
      <div style="display:flex;justify-content:space-between;font-size:0.62rem;color:var(--text-dim);margin-top:0.15rem;">
        <span>Type: ${{c.type}}</span>
        ${{pthBadge}}
      </div>
      ${{hashExtra}}
      <div style="display:flex;justify-content:space-between;font-size:0.6rem;color:var(--text-muted);margin-top:0.25rem;border-top:1px solid rgba(255,255,255,0.03);padding-top:0.2rem;">
        <span>Paths unlocked: <strong>${{c.unlockedPaths}}</strong></span>
        <span>${{c.lastUsed}}</span>
      </div>
    `;
    
    if (c.status === 'valid' || c.isPth) {{
      card.style.cursor = 'pointer';
      card.onclick = () => doPivot(c.user);
      card.title = `Click to pivot to ${{c.user}}`;
    }}
    
    el.appendChild(card);
  }});
}}

/* ── Engagement context strip ─────────────────────────────── */
function renderEngagementStrip(s) {{
  const el = document.getElementById('engagement-strip');
  if (!el) return;
  const dash = s.dashboard || {{}};
  const owned = (s.player?.owned || []).length;
  const pivot = (s.player || {{}}).pivot || 'none';
  const eff = s.effective_progress || s.progress || {{}};
  const wr = s.workspace_readiness || (typeof WorkspaceVars !== 'undefined' ? WorkspaceVars.readiness() : {{}});
  const phases = [];
  if (eff.scan) phases.push('recon');
  if (eff.enum_users) phases.push('enum');
  if (eff.loot) phases.push('loot');
  if (eff.acls) phases.push('acls');
  if (eff.exploit) phases.push('exploit');
  let stage = dash.stage_label || (phases.length ? phases.join(' → ') : 'Starting');
  let hint = '';
  if (s.workspace_required) {{
    stage = 'Create or open workspace';
    hint = 'Name this engagement (e.g. corp-internal, prod-forest) — not the target IP.';
  }} else if (!wr.scan_ready) {{
    stage = '① Set target';
    hint = 'Enter DC IP in the terminal bar (bottom) or Commands / Cheatsheet vars → Discovery.';
  }} else if (!wr.auth_ready) {{
    stage = '② Authenticate';
    hint = 'Fill username + password (or NTLM hash in vars) → Authenticate.';
  }} else if (!eff.scan) {{
    stage = 'Ready — run Discovery';
    hint = 'Vars are set. Click Discovery to enumerate the domain.';
  }} else if (!pivot || pivot === 'none') {{
    stage = '③ Establish pivot';
    hint = 'Click Authenticate to verify credentials and set your pivot.';
  }} else if (eff.exploit && s.next_action?.source === 'postex') {{
    hint = 'Shell access likely via machine account — pivot may be Kerberos-only.';
  }} else {{
    hint = 'Orange star = pivot · green/diamond = BloodHound overlay (inventory, not compromise).';
  }}
  el.innerHTML =
    '<div class="es-stage">' + escHtml(stage) + '</div>' +
    '<div class="es-meta">' + owned + ' owned · pivot <strong>' + escHtml(pivot) + '</strong>' +
      (phases.length ? ' · ' + escHtml(phases.join(' · ')) : '') + '</div>' +
    (hint ? '<div class="es-hint">' + escHtml(hint) + '</div>' : '');
}}

/* ── Next Best Action (Syntax Highlighted Command) ────────── */
function renderNextBestAction(s) {{
  const el = document.getElementById('next-action-container');
  el.innerHTML = '';
  const na = s.next_action || {{}};
  const obj = s.objective || {{}};
  const progress = s.effective_progress || s.progress || {{}};
  const creds = s.creds || [];
  const pivot = s.player?.pivot;

  let command = na.command || '';
  let reason = na.reason || '';
  let impact = na.impact || '';
  let headline = na.headline || '';
  let source = na.source || 'phase';

  if (!command) {{
    if (!progress.scan) {{
      command = 'admapper scan -H ' + (s.meta?.workspace || s.meta?.dc_ip || '<Target_IP>');
      reason = 'Perform initial reconnaissance and domain naming context mapping.';
      impact = 'Establishes domain connectivity and caches DC endpoints.';
      headline = 'Unauthenticated discovery';
    }} else if (!progress.enum_users) {{
      command = 'admapper enum users -w ' + (s.meta?.workspace || 'default');
      reason = 'Enumerate domain accounts from cached recon.';
      impact = 'Builds roast/spray target inventory.';
      headline = 'User enumeration';
    }} else if (!creds.length) {{
      command = 'admapper asreproast -w ' + (s.meta?.workspace || 'default');
      reason = 'No verified credentials in dashboard view yet.';
      impact = 'Recover crackable AS-REP hashes.';
      headline = 'Credential access';
    }} else if (!pivot) {{
      const firstUser = creds[0]?.user || 'user';
      command = 'admapper run -w ' + (s.meta?.workspace || 'default') + ' -u ' + firstUser + " -p '<password>'";
      reason = 'Promote a pivot to unlock authenticated graph analysis.';
      impact = 'Runs authenticated LDAP/SMB enum as the chosen user.';
      headline = 'Establish pivot';
    }} else if (obj.command) {{
      command = obj.command;
      reason = obj.headline || 'Execute mapped attack path.';
      impact = 'Privilege escalation via graph edge.';
      headline = obj.headline || 'Attack path';
    }}
  }}

  const sourceLabel = {{
    postex: 'Post-ex playbook',
    objective: 'Attack graph',
    mission: 'ACL mission',
    phase: 'Pipeline phase',
    fallback: 'Review',
  }}[source] || 'Suggested';

  const hijackOps = hijackPostexOps(s);
  const showPostexBtn = hijackOps.length > 0 && (
    na.postex_runnable || na.source === 'postex' ||
    (progress.exploit || (s.effective_progress || {{}}).exploit)
  );
  const prefPostexOp = na.op_id || (hijackOps[0] && hijackOps[0].id) || '';
  const postexBtnHtml = showPostexBtn
    ? '<button type="button" class="postex-run-btn" data-postex-op="' + escHtml(prefPostexOp) + '">' +
      '<i class="fa-solid fa-terminal"></i> Establish Reverse Shell</button>'
    : '';

  el.innerHTML = `
    <div class="next-action-card">
      <div class="next-action-source">${{escHtml(sourceLabel)}}</div>
      ${{headline ? '<div class="next-action-headline">' + escHtml(headline) + '</div>' : ''}}
      <div style="font-size:0.62rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.3rem;">Active Command</div>
      <div class="syntax-code-block" data-copy-val="${{escHtml(command)}}" data-copy-label="Suggested Command" title="Click to copy command">
        <span class="mono">${{highlightCommand(command)}}</span>
        <i class="fa-regular fa-copy copy-icon"></i>
      </div>
      <div style="margin-top:0.45rem;font-size:0.7rem;line-height:1.35;">
        <div style="color:var(--text);margin-bottom:0.15rem;"><strong>Reason:</strong> ${{escHtml(reason)}}</div>
        <div style="color:var(--text-dim);"><strong>Impact:</strong> ${{escHtml(impact)}}</div>
      </div>
      ${{postexBtnHtml}}
    </div>
  `;
}}

function highlightCommand(cmd) {{
  return cmd.replace(/(admapper|scan|enum|exploit|asreproast|kerberoast|run|spray|brief|evil-winrm)/g, '<span style="color:var(--cyan);font-weight:600;">$1</span>')
            .replace(/(^|\\s)(-w|-H|-u|-p|-i|-d|--rounds)\\b/g, '$1<span style="color:var(--orange);">$2</span>')
            .replace(/(<[^>]+>)/g, '<span style="color:var(--yellow);font-weight:500;">$1</span>');
}}

/* ── Operational Pipeline Track ───────────────────────────── */
function renderOperationalPipeline(s) {{
  const el = document.getElementById('pipeline-track');
  el.innerHTML = '';
  const progress = s.effective_progress || s.progress || {{}};
  const creds = s.creds || [];
  const pivot = s.player?.pivot;
  const isExploited = progress.exploit;
  
  const stages = [
    {{ name: 'Discovery', status: progress.scan ? 'done' : 'active', tooltip: 'Discovery scan status' }},
    {{ name: 'Inventory', status: progress.scan ? (progress.enum_users ? 'done' : 'active') : 'blocked', tooltip: 'Requires Discovery scan completion.' }},
    {{ name: 'Creds', status: progress.enum_users ? (creds.length > 0 ? 'done' : 'active') : 'blocked', tooltip: 'Requires unauthenticated enumeration.' }},
    {{ name: 'Auth', status: creds.length > 0 ? (pivot ? 'done' : 'active') : 'blocked', tooltip: 'Requires valid credentials verification.' }},
    {{ name: 'Attack', status: pivot ? (isExploited ? 'done' : 'active') : 'blocked', tooltip: 'Requires active authenticated pivot.' }},
    {{ name: 'Pivot', status: isExploited ? 'done' : 'blocked', tooltip: 'Requires successful exploit to pivot.' }},
    {{ name: 'Synthesis', status: isExploited ? 'active' : 'blocked', tooltip: 'Requires exploitation results.' }}
  ];
  
  stages.forEach((st, idx) => {{
    const node = document.createElement('div');
    node.className = `pipeline-node ${{st.status}}`;
    node.innerHTML = `
      <div class="circle" title="${{st.tooltip}}">${{idx + 1}}</div>
      <div class="label">${{st.name}}</div>
    `;
    el.appendChild(node);
    
    if (idx < stages.length - 1) {{
      const line = document.createElement('div');
      line.className = `pipeline-line ${{st.status === 'done' ? 'done' : ''}}`;
      el.appendChild(line);
    }}
  }});
}}

/* ── Actions Grouped Console ──────────────────────────────── */
function renderActionsRedesign(s) {{
  const container = document.getElementById('action-buttons-redesign');
  container.innerHTML = '';
  const progress = s.effective_progress || s.progress || {{}};
  const serverActions = s.actions || [];

  if (serverActions.length) {{
    const groupDiv = document.createElement('div');
    groupDiv.className = 'action-group-redesign';
    groupDiv.innerHTML = '<div class="group-title">Workspace actions</div>';
    const btnsDiv = document.createElement('div');
    btnsDiv.className = 'group-buttons';
    serverActions.forEach(function (act) {{
      const btn = document.createElement('button');
      btn.className = 'btn' + (act.required ? ' btn-primary' : '');
      btn.title = act.reason || '';
      btn.disabled = !act.enabled;
      if (!act.enabled) btn.style.opacity = '0.35';
      const fnMap = {{
        scan: 'doDiscovery()',
        enum: 'doEnum()',
        asreproast: 'doAsrep()',
        kerberoast: 'doKerb()',
        spray: 'triggerSprayPrompt()',
        run: 'doAuth()',
        acls: 'doAcls()',
        exploit: 'doExploit()',
      }};
      const actionKey = String(act.action || '');
      if (act.enabled && fnMap[actionKey]) btn.setAttribute('onclick', fnMap[actionKey]);
      btn.textContent = act.button || act.action || 'Action';
      btnsDiv.appendChild(btn);
    }});
    groupDiv.appendChild(btnsDiv);
    container.appendChild(groupDiv);
    if (opRunning) setButtonsDisabled(true);
    return;
  }}

  const hasCreds = (s.creds || []).length > 0;
  const pivot = s.player?.pivot;
  
  const groups = [
    {{
      name: 'Recon & Discovery',
      actions: [
        {{ name: 'Discovery', fn: 'triggerDiscoveryPrompt()', enabled: true, tooltip: 'Map target IP network contexts.' }},
        {{ name: 'Enum Users', fn: 'doEnum()', enabled: progress.scan, tooltip: 'Map domain users (Requires Discovery).' }}
      ]
    }},
    {{
      name: 'Credentials & Auth',
      actions: [
        {{ name: 'AS-REP Roast', fn: 'doAsrep()', enabled: progress.enum_users, tooltip: 'Roast disabled pre-auth accounts (Requires Inventory).' }},
        {{ name: 'Kerberoast', fn: 'doKerb()', enabled: progress.enum_users, tooltip: 'Roast SPN service accounts (Requires Inventory).' }},
        {{ name: 'Audit ACLs', fn: 'doAcls()', enabled: progress.scan && pivot, tooltip: 'Perform AD ACL relationship mapping (Requires Pivot).' }}
      ]
    }},
    {{
      name: 'Exploitation & Lateral',
      actions: [
        {{ name: 'Auto Exploit', fn: 'doExploit()', enabled: progress.scan, tooltip: 'Trigger chained auto-exploitation on mapped targets.' }},
        {{ name: 'Password Spray', fn: 'triggerSprayPrompt()', enabled: progress.enum_users, tooltip: 'Launch domain password spray (Requires Inventory).' }}
      ]
    }},
    {{
      name: 'Synthesis & Reporting',
      actions: [
        {{ name: 'Generate Brief', fn: 'doBrief()', enabled: progress.exploit, tooltip: 'Compile operator engagement brief (Requires Attack).' }}
      ]
    }}
  ];
  
  groups.forEach(g => {{
    const groupDiv = document.createElement('div');
    groupDiv.className = 'action-group-redesign';
    groupDiv.innerHTML = `<div class="group-title">${{escHtml(g.name)}}</div>`;
    
    const btnsDiv = document.createElement('div');
    btnsDiv.className = 'group-buttons';
    
    g.actions.forEach(act => {{
      const btn = document.createElement('button');
      btn.className = 'btn';
      btn.title = act.tooltip;
      
      if (!act.enabled) {{
        btn.disabled = true;
        btn.style.opacity = '0.3';
      }} else {{
        btn.setAttribute('onclick', act.fn);
      }}
      btn.textContent = act.name;
      btnsDiv.appendChild(btn);
    }});
    
    groupDiv.appendChild(btnsDiv);
    container.appendChild(groupDiv);
  }});
  
  if (opRunning) {{
    setButtonsDisabled(true);
  }}
}}

/* ── Collapsible Findings Accordion ───────────────────────── */
function renderFindingsFeed(s) {{
  const el = document.getElementById('findings-accordion');
  el.innerHTML = '';
  
  const raw = s.findings?.findings || s.findings?.finding || [];
  const highlights = s.highlights || [];
  const intel = s.engagement_intel || {{}};
  
  const allFindings = [];
  
  raw.forEach(f => {{
    const title = f.title || f.highlight || f.key || '';
    if (!title) return;
    let severity = (f.severity || 'medium').toLowerCase();
    allFindings.push({{
      title: title + (f.detail ? ' — ' + f.detail : ''),
      severity: severity
    }});
  }});
  
  highlights.forEach(h => {{
    let sev = 'medium';
    if (h.toLowerCase().includes('unconstrained') || h.toLowerCase().includes('delegation')) {{
      sev = 'high';
    }}
    allFindings.push({{ title: h, severity: sev }});
  }});
  
  const sections = intel.sections || [];
  sections.forEach(sec => {{
    (sec.items || []).forEach(item => {{
      if (item.highlight) {{
        allFindings.push({{
          title: item.label || item.highlight,
          severity: (item.severity || 'medium').toLowerCase()
        }});
      }}
    }});
  }});
  
  const groups = {{
    critical: [],
    high: [],
    medium: [],
    info: []
  }};
  
  allFindings.forEach(f => {{
    if (groups[f.severity]) {{
      groups[f.severity].push(f.title);
    }} else {{
      groups.info.push(f.title);
    }}
  }});
  
  const sevLabels = {{
    critical: {{ name: 'Critical Severity', class: 'crit', icon: 'fa-triangle-exclamation' }},
    high: {{ name: 'High Severity', class: 'high', icon: 'fa-circle-exclamation' }},
    medium: {{ name: 'Medium Severity', class: 'med', icon: 'fa-circle-question' }},
    info: {{ name: 'Informational', class: 'info', icon: 'fa-circle-info' }}
  }};
  
  let totalFindings = allFindings.length;
  document.getElementById('finding-count-redesign').textContent = totalFindings;
  
  Object.keys(groups).forEach(key => {{
    const list = groups[key];
    if (list.length === 0) return;
    
    const meta = sevLabels[key];
    const item = document.createElement('div');
    item.className = 'accordion-section';
    
    const uniqueList = [...new Set(list)];
    
    item.innerHTML = `
      <div class="accordion-header ${{meta.class}}" onclick="toggleAccordion(this)">
        <span><i class="fa-solid ${{meta.icon}}"></i> ${{meta.name}} (${{uniqueList.length}})</span>
        <i class="fa-solid fa-chevron-down chevron"></i>
      </div>
      <div class="accordion-content">
        <ul class="findings-list">
          ${{uniqueList.map(f => `<li>${{escHtml(f)}}</li>`).join('')}}
        </ul>
      </div>
    `;
    el.appendChild(item);
  }});
  
  if (totalFindings === 0) {{
    el.innerHTML = '<div class="nd-empty">No security findings mapped</div>';
  }}
}}

function toggleAccordion(header) {{
  const section = header.parentElement;
  section.classList.toggle('open');
}}

/* ── Node details inspector ───────────────────────────────── */
function showNodeDetail(nodeId) {{
  const panel = document.getElementById('panel-node-detail');
  const content = document.getElementById('node-detail-content');
  const node = graphNodes.find(n => n.id === nodeId);
  if (!node) {{ panel.style.display = 'none'; return; }}

  panel.style.display = '';
  selectedNodeId = nodeId;

  const typeMap = {{
    dc: 'Domain Controller', operator: 'Pivot Identity', user: 'Domain User',
    computer: 'Computer / Host', group: 'AD Group', gmsa: 'gMSA Account',
    domain: 'Active Directory Domain', highvalue: 'High-Value Target'
  }};
  const nodeType = typeMap[node.group] || node.group || 'Unknown';

  const inEdges = graphEdges.filter(e => e.to === nodeId);
  const outEdges = graphEdges.filter(e => e.from === nodeId);

  let html = '<div class="node-detail">';
  html += '<div class="nd-type">' + escHtml(nodeType) + '</div>';
  html += '<div class="nd-name">' + escHtml(node.label || node.username || node.id) + '</div>';

  if (node.username) {{
    html += '<div class="nd-row"><span>SAMAccountName</span><strong>' + escHtml(node.username) + '</strong></div>';
  }}
  if (node.title) {{
    html += '<div class="nd-row" style="flex-direction:column;gap:0.15rem"><span style="color:var(--text-muted);font-weight:600">Attributes</span>';
    html += '<span style="font-size:0.65rem;color:var(--text-dim);white-space:pre-wrap;font-family:var(--mono)">' + escHtml(node.title) + '</span></div>';
  }}

  if (inEdges.length) {{
    html += '<div class="nd-edges"><div style="font-size:0.62rem;color:var(--text-muted);font-weight:700;margin-bottom:0.2rem">Inbound Relations (' + inEdges.length + ')</div>';
    inEdges.slice(0, 8).forEach(e => {{
      const src = graphNodes.find(n => n.id === e.from);
      html += '<div class="nd-edge"><span>' + escHtml(src?.label || e.from) + '</span><span class="mono" style="color:var(--orange);font-size:0.6rem">' + escHtml(e.label) + '</span></div>';
    }});
    html += '</div>';
  }}

  if (outEdges.length) {{
    html += '<div class="nd-edges"><div style="font-size:0.62rem;color:var(--text-muted);font-weight:700;margin-bottom:0.2rem">Outbound Relations (' + outEdges.length + ')</div>';
    outEdges.slice(0, 8).forEach(e => {{
      const tgt = graphNodes.find(n => n.id === e.to);
      html += '<div class="nd-edge"><span class="mono" style="color:var(--accent);font-size:0.6rem">' + escHtml(e.label) + '</span><span>' + escHtml(tgt?.label || e.to) + '</span></div>';
    }});
    html += '</div>';
  }}

  html += '</div>';
  content.innerHTML = html;
}}

/* ── Pivot Card ───────────────────────────────────────────── */
function renderPivotCard(s) {{
  const el = document.getElementById('pivot-display');
  const pivot = (s.player || {{}}).pivot;
  const meta = s.meta || {{}};
  const methods = (s.player || {{}}).owned_methods || {{}};
  if (!pivot) {{
    el.innerHTML = '<div class="nd-empty">No active pivot established</div>';
    return;
  }}
  const initial = pivot.charAt(0).toUpperCase();
  const domain = meta.domain && meta.domain !== '???' ? meta.domain : '';
  const method = methods[pivot.toLowerCase()] || methods[pivot.toLowerCase() + '$'] || '';
  let note = '';
  if (s.player?.pivot_protected) {{
    note = 'Protected Users — Kerberos only (no SMB/NTLM to DC)';
  }} else if (pivot.endsWith('$')) {{
    note = 'Machine account — use for WinRM/shell, not LDAP pivot analysis';
  }}
  el.innerHTML = `
    <div class="pivot-card">
      <div class="avatar">${{escHtml(initial)}}</div>
      <div class="info">
        <div class="name">${{escHtml(pivot)}}</div>
        <div class="detail">${{domain ? escHtml(domain) + ' · ' : ''}}Active pivot</div>
        ${{method ? '<div class="pivot-method">via ' + escHtml(method) + '</div>' : ''}}
        ${{note ? '<div class="pivot-note">' + escHtml(note) + '</div>' : ''}}
      </div>
    </div>
  `;
}}

/* ── Header inline edit (workspace name + DC IP) ─────────── */
function bindHeaderInlineEdit() {{
  document.querySelectorAll('.inline-edit').forEach(function (el) {{
    if (el.dataset.inlineBound === '1') return;
    el.dataset.inlineBound = '1';
    el.addEventListener('click', function () {{ startHeaderInlineEdit(el); }});
  }});
}}

function startHeaderInlineEdit(el) {{
  if (!el || el.querySelector('input')) return;
  const field = el.dataset.field || '';
  const current = el.textContent.trim();
  const val = (current === '…' || current === '...') ? '' : current;
  if (field === 'workspace' && state && state.workspace_required) return;

  const inp = document.createElement('input');
  inp.className = 'header-inline-input';
  inp.value = val;
  inp.type = field === 'dc' ? 'text' : 'text';
  inp.placeholder = field === 'dc' ? '192.168.10.10' : 'corp-internal';
  el.textContent = '';
  el.appendChild(inp);
  inp.focus();
  inp.select();

  function restore(display) {{
    el.textContent = display;
  }}

  function commit() {{
    const next = inp.value.trim();
    if (field === 'workspace') {{
      if (!next || next === (state.meta && state.meta.workspace)) {{
        restore(state.meta && state.meta.workspace ? state.meta.workspace : '…');
        return;
      }}
      fetch('/api/workspace/rename', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ name: next }})
      }}).then(function (r) {{ return r.json(); }}).then(function (data) {{
        if (data.error) {{
          termLogSemantic(data.error, 'error');
          restore(state.meta && state.meta.workspace ? state.meta.workspace : '…');
          return;
        }}
        if (data.state && typeof renderState === 'function') renderState(data.state);
        else restore(next);
      }}).catch(function () {{
        restore(state.meta && state.meta.workspace ? state.meta.workspace : '…');
      }});
      return;
    }}
    if (field === 'dc') {{
      if (!next) {{
        restore((state.meta && (state.meta.dc_host || state.meta.dc_ip)) || '...');
        return;
      }}
      if (typeof WorkspaceVars !== 'undefined') {{
        WorkspaceVars.set({{ DC_IP: next }});
        WorkspaceVars.persistNow();
      }}
      restore(next);
      const termIp = document.getElementById('input-ip');
      if (termIp) termIp.value = next;
      return;
    }}
    restore(next || current);
  }}

  inp.addEventListener('blur', commit);
  inp.addEventListener('keydown', function (e) {{
    if (e.key === 'Enter') {{ e.preventDefault(); inp.blur(); }}
    if (e.key === 'Escape') {{ inp.value = val; inp.blur(); }}
  }});
}}

function toggleGraphLegend() {{
  const legend = document.getElementById('graph-legend');
  if (legend) legend.classList.toggle('collapsed');
}}

function isPlaceholderNode(n) {{
  if (!n) return true;
  if (n.id === 'operator' || n.group === 'operator') return true;
  const lbl = String(n.label || '').trim().toUpperCase();
  return lbl === 'OPERATOR';
}}

function graphEmptyInfo() {{
  if (state.workspace_required) {{
    return {{ empty: true, msg: 'Create or open a workspace to begin mapping the domain.' }};
  }}
  const nodes = ((state.graph || {{}}).nodes) || [];
  const real = nodes.filter(function (n) {{ return !isPlaceholderNode(n); }});
  if (!real.length) {{
    const wr = state.workspace_readiness || (typeof WorkspaceVars !== 'undefined' ? WorkspaceVars.readiness() : {{}});
    if (!wr.scan_ready) {{
      return {{ empty: true, msg: 'Click DC in the header or terminal bar to set target IP, then run Discovery.' }};
    }}
    return {{ empty: true, msg: 'Run Discovery to populate the attack graph.' }};
  }}
  return {{ empty: false }};
}}

function showGraphEmpty(msg) {{
  const overlay = document.getElementById('graph-empty');
  const msgEl = document.getElementById('graph-empty-msg');
  if (overlay) overlay.style.display = 'flex';
  if (msgEl) msgEl.textContent = msg;
  if (network) {{
    network.setData({{ nodes: new vis.DataSet([]), edges: new vis.DataSet([]) }});
  }}
  graphNodes = [];
  graphEdges = [];
}}

function hideGraphEmpty() {{
  const overlay = document.getElementById('graph-empty');
  if (overlay) overlay.style.display = 'none';
}}

/* ── vis-network Graph Redesign & Controls ────────────────── */
function renderGraph(graphData) {{
  const empty = graphEmptyInfo();
  if (empty.empty) {{
    showGraphEmpty(empty.msg);
    return;
  }}
  hideGraphEmpty();

  const nodes = (graphData.nodes || []).filter(function (n) {{ return !isPlaceholderNode(n); }});
  if (!nodes.length) {{
    showGraphEmpty(graphEmptyInfo().msg || 'Run Discovery to populate the attack graph.');
    return;
  }}

  const pivotUser = (state.player || {{}}).pivot || '';
  const nodeIds = new Set(nodes.map(function (n) {{ return n.id; }}));
  const edges = (graphData.edges || []).filter(function (e) {{
    return nodeIds.has(e.from) && nodeIds.has(e.to);
  }});

  const nextDataKey = nodes.map(function (n) {{ return n.id; }}).sort().join('|');
  if (nextDataKey !== graphDataKey) {{
    graphDataKey = nextDataKey;
    graphStructureKey = '';
  }}

  graphNodes = nodes.map(n => {{
    const isPivot = n.username && n.username.toLowerCase() === pivotUser.toLowerCase();
    const isOwned = n.group === 'operator' || n.identity_role === 'owned' || 
                  (state.player && state.player.owned && n.username && 
                   state.player.owned.map(u => u.toLowerCase()).includes(n.username.toLowerCase()));
    const isDC = n.group === 'dc';
    const isHV = n.group === 'highvalue';
    const isGroup = n.group === 'group';
    const isComputer = n.group === 'computer';
    const isGmsa = n.group === 'gmsa';
    const isKerberoastable = n.kerberoastable || n.group === 'kerberoastable';
    const isAsrep = n.asrep_roastable || n.group === 'asrep';
    const isDomain = n.group === 'domain';
    const isUser = n.group === 'user' || (!isPivot && !isDC && !isOwned && !isHV && !isGroup && !isComputer && !isGmsa && !isDomain);

    let size = 16;
    if (isPivot) size = 32;
    else if (isDC || isDomain) size = 28;
    else if (isHV) size = 24;
    else if (isGroup || isGmsa) size = 22;
    else if (isKerberoastable || isAsrep) size = 22;
    else if (isComputer) size = 18;

    let iconChar = '\\uf007';
    let iconColor = '#94a3b8';
    let shadowColor = 'rgba(0,0,0,0.5)';
    let shadowSize = 6;

    if (isPivot) {{
      iconChar = '\\uf005';
      iconColor = '#f0883e';
      shadowColor = 'rgba(240, 136, 62, 0.4)';
      shadowSize = 12;
    }} else if (isOwned) {{
      iconColor = '#3fb950';
      shadowColor = 'rgba(63, 185, 80, 0.5)';
      shadowSize = 10;
    }}

    if (!isPivot) {{
      if (isDC) {{
        iconChar = '\\uf233';
        if (!isOwned) iconColor = '#f85149';
      }} else if (isDomain) {{
        iconChar = '\\uf0ac';
        if (!isOwned) iconColor = '#f85149';
      }} else if (isHV) {{
        iconChar = '\\uf521';
        if (!isOwned) iconColor = '#f85149';
      }} else if (isGroup) {{
        iconChar = '\\uf0c0';
        if (!isOwned) iconColor = '#d29922';
      }} else if (isComputer) {{
        iconChar = '\\uf390';
        if (!isOwned) iconColor = '#58a6ff';
      }} else if (isGmsa) {{
        iconChar = '\\uf4ff';
        if (!isOwned) iconColor = '#56d4dd';
      }} else if (isKerberoastable) {{
        iconChar = '\\uf084';
        if (!isOwned) iconColor = '#ec4899';
      }} else if (isAsrep) {{
        iconChar = '\\uf09c';
        if (!isOwned) iconColor = '#bc8cff';
      }}
    }}

    let label = n.label || n.username || n.id;
    label = label.replace(/^[\\u2605\\u2606\\u2726]\\s*/g, '');
    if (label.length > 20) label = label.substring(0, 18) + '...';

    const showLabel = isPivot || isOwned || isDC || isDomain || isHV || isKerberoastable || isAsrep
      || (isUser && !isGroup);

    return {{
      ...n,
      label,
      shape: 'icon',
      icon: {{
        face: '"Font Awesome 6 Free"',
        weight: '900',
        code: iconChar,
        size: size,
        color: iconColor
      }},
      shadow: {{ enabled: true, size: shadowSize, color: shadowColor, x: 0, y: 0 }},
      font: {{ color: '#c9d1d9', size: showLabel ? (isPivot ? 12 : (isDC || isDomain ? 11 : 9)) : 0, strokeWidth: 2, strokeColor: '#0d1117' }},
    }};
  }});

  graphEdges = edges.map(e => {{
    const lbl = String(e.label || '').trim();
    const lowerLbl = lbl.toLowerCase();
    let edgeColor = '#30363d';
    let width = 1.5;
    let dashes = e.dashes || false;

    if (e.pivot_edge || e.path_id) {{
      edgeColor = '#f0883e';
      width = 3.0;
      dashes = [4, 4];
    }} else if (['genericall', 'genericwrite', 'writedacl', 'writeowner', 'owns', 'dcsync', 'getchangesall', 'getchanges', 'allextendedrights', 'addmember', 'allowedtoact'].some(k => lowerLbl.includes(k))) {{
      edgeColor = '#f85149';
      width = 1.8;
    }} else if (['adminto', 'localadmin'].some(k => lowerLbl.includes(k))) {{
      edgeColor = '#d29922';
      width = 1.8;
    }} else if (['memberof', 'contains', 'member of domain'].some(k => lowerLbl.includes(k))) {{
      edgeColor = '#30363d';
      width = 1.0;
    }}

    return {{
      ...e,
      label: lbl,
      smooth: {{ type: 'continuous' }},
      font: {{
        color: '#8b949e',
        size: 8,
        face: 'var(--font)',
        strokeWidth: 2,
        strokeColor: '#0d1117',
        align: 'top'
      }},
      color: {{
        color: edgeColor,
        highlight: '#58a6ff',
        hover: '#58a6ff',
        opacity: e.pivot_edge || e.path_id ? 1.0 : 0.6
      }},
      width: width,
      dashes: dashes,
    }};
  }});

  if (!graphFilterUserSet && nodes.length > 30) {{
    currentGraphFilter = 'highvalue';
  }}

  setGraphFilter(currentGraphFilter);
}}

function updateGraphFilterButtons() {{
  document.querySelectorAll('[data-graph-filter]').forEach(function (btn) {{
    btn.classList.toggle('active', btn.dataset.graphFilter === currentGraphFilter);
  }});
}}

function applyRadialLayout(nodes, edges) {{
  if (!nodes.length) return nodes;
  const out = nodes.map(function (n) {{ return Object.assign({{}}, n); }});
  let hubId = null;
  for (let i = 0; i < out.length; i++) {{
    if (out[i].group === 'domain') {{ hubId = out[i].id; break; }}
  }}
  if (!hubId) {{
    const deg = {{}};
    (edges || []).forEach(function (e) {{
      deg[e.from] = (deg[e.from] || 0) + 1;
      deg[e.to] = (deg[e.to] || 0) + 1;
    }});
    const ranked = Object.keys(deg).sort(function (a, b) {{ return deg[b] - deg[a]; }});
    hubId = ranked[0] || out[0].id;
  }}
  const spokes = out.filter(function (n) {{ return n.id !== hubId; }});
  const radius = Math.min(400, 90 + spokes.length * 16);
  spokes.forEach(function (n, i) {{
    const angle = (2 * Math.PI * i) / Math.max(spokes.length, 1) - Math.PI / 2;
    n.x = radius * Math.cos(angle);
    n.y = radius * Math.sin(angle);
  }});
  const hub = out.find(function (n) {{ return n.id === hubId; }});
  if (hub) {{ hub.x = 0; hub.y = 0; }}
  return out;
}}

function preserveNodePositions(nodes, edges, forceLayout) {{
  if (!nodes.length) return nodes;
  const positioned = nodes.map(function (n) {{ return Object.assign({{}}, n); }});
  let saved = {{}};
  if (network) {{
    try {{ saved = network.getPositions(); }} catch (e) {{}}
  }}
  let missing = 0;
  positioned.forEach(function (n) {{
    const p = saved[n.id];
    if (p && p.x != null && p.y != null) {{
      n.x = p.x;
      n.y = p.y;
      return;
    }}
    if (nodeData) {{
      try {{
        const old = nodeData.get(n.id);
        if (old && old.x != null && old.y != null) {{
          n.x = old.x;
          n.y = old.y;
          return;
        }}
      }} catch (e) {{}}
    }}
    missing += 1;
  }});
  if (forceLayout || missing === positioned.length) {{
    return applyRadialLayout(positioned, edges);
  }}
  if (missing > 0) {{
    const placed = applyRadialLayout(
      positioned.filter(function (n) {{ return n.x == null || n.y == null; }}),
      edges
    );
    const byId = {{}};
    placed.forEach(function (n) {{ byId[n.id] = n; }});
    return positioned.map(function (n) {{ return byId[n.id] || n; }});
  }}
  return positioned;
}}

function graphPhysicsOptions() {{
  return {{
    enabled: true,
    stabilization: {{ iterations: 120, updateInterval: 25 }},
    barnesHut: {{
      gravitationalConstant: -8000,
      centralGravity: 0.08,
      springLength: 200,
      springConstant: 0.03,
      damping: 0.15,
      avoidOverlap: 0.35,
    }},
  }};
}}

function graphInteractionOptions() {{
  return {{
    hover: true,
    tooltipDelay: 120,
    zoomView: true,
    dragView: true,
    dragNodes: true,
    multiselect: false,
    navigationButtons: false,
    keyboard: {{ enabled: true, bindToWindow: false }},
  }};
}}

function relayoutNetwork() {{
  if (!network || !nodeData) return;
  const nodes = nodeData.get();
  const edges = edgeData ? edgeData.get() : [];
  const laid = applyRadialLayout(nodes, edges);
  nodeData.update(laid);
  network.setOptions({{ physics: graphPhysicsOptions() }});
  network.once('stabilizationIterationsDone', function () {{
    network.setOptions({{ physics: {{ enabled: false }} }});
    physicsOn = false;
    network.fit({{ animation: {{ duration: 350 }} }});
  }});
}}

function setGraphFilter(filter) {{
  if (filter) {{
    currentGraphFilter = filter;
    graphFilterUserSet = true;
  }}
  updateGraphFilterButtons();
  
  if (!graphNodes.length) return;
  
  const container = document.getElementById('graph-canvas');
  if (!container) return;
  
  const filteredNodes = graphNodes.filter(n => {{
    if (filter === 'all') return true;
    
    const isPivot = n.username && n.username.toLowerCase() === ((state.player || {{}}).pivot || '').toLowerCase();
    const isOwned = n.group === 'operator' || n.identity_role === 'owned' || 
                  (state.player && state.player.owned && n.username && 
                   state.player.owned.map(u => u.toLowerCase()).includes(n.username.toLowerCase()));
    const isDC = n.group === 'dc';
    const isHV = n.group === 'highvalue';
    
    if (filter === 'highvalue') {{
      return isDC || isHV || isPivot || isOwned;
    }}
    if (filter === 'compromised') {{
      const compromisedUsers = new Set();
      (state.creds || []).forEach(c => compromisedUsers.add(c.user.toLowerCase()));
      (state.pth_sessions || []).forEach(p => compromisedUsers.add(p.account.toLowerCase()));
      return isPivot || isOwned || compromisedUsers.has((n.username || '').toLowerCase());
    }}
    if (filter === 'path') {{
      const pathNodeIds = new Set();
      graphEdges.forEach(e => {{
        if (e.path_id || e.pivot_edge) {{
          pathNodeIds.add(e.from);
          pathNodeIds.add(e.to);
        }}
      }});
      return pathNodeIds.has(n.id) || isPivot || isOwned;
    }}
    return true;
  }});
  
  const visibleNodeIds = new Set(filteredNodes.map(n => n.id));
  const filteredEdges = graphEdges.filter(e => visibleNodeIds.has(e.from) && visibleNodeIds.has(e.to));

  // SharpHound overlay (Feature 1): merge imported layer, kept separate from graph.json
  let mergedNodes = filteredNodes;
  let mergedEdges = filteredEdges;
  if (typeof BloodHoundOverlay !== 'undefined') {{
    const bh = BloodHoundOverlay.overlayFor(filter);
    if (bh) {{
      mergedNodes = mergedNodes.concat(bh.nodes);
      mergedEdges = mergedEdges.concat(bh.edges);
    }}
  }}
  if (typeof SharpHoundImport !== 'undefined') {{
    const ov = SharpHoundImport.overlayFor(filter);
    if (ov) {{
      mergedNodes = mergedNodes.concat(ov.nodes);
      mergedEdges = mergedEdges.concat(ov.edges);
    }}
  }}

  const structureKey = mergedNodes.length + ':' + mergedEdges.length + ':' + currentGraphFilter;
  const forceLayout = structureKey !== graphStructureKey;
  graphStructureKey = structureKey;
  mergedNodes = preserveNodePositions(mergedNodes, mergedEdges, forceLayout && !network);

  const networkData = {{
    nodes: new vis.DataSet(mergedNodes),
    edges: new vis.DataSet(mergedEdges)
  }};

  if (network) {{
    network.setData(networkData);
    nodeData = networkData.nodes;
    edgeData = networkData.edges;
    if (forceLayout) {{
      network.fit({{ animation: {{ duration: 250 }} }});
    }}
    return;
  }}

  const graphArea = container.parentElement;
  container.style.width = graphArea.clientWidth + 'px';
  container.style.height = graphArea.clientHeight + 'px';

  network = new vis.Network(container, networkData, {{
    width: '100%',
    height: '100%',
    autoResize: true,
    physics: {{ enabled: false }},
    interaction: graphInteractionOptions(),
    edges: {{
      arrows: {{ to: {{ enabled: true, scaleFactor: 0.6 }} }},
      smooth: {{ type: 'continuous' }},
    }},
  }});
  
  nodeData = networkData.nodes;
  edgeData = networkData.edges;

  network.fit({{ animation: false }});
  physicsOn = false;

  const ro = new ResizeObserver(function () {{
    if (network) {{ network.redraw(); }}
  }});
  ro.observe(graphArea);

  network.on('click', function (params) {{
    if (params.nodes.length) {{
      const nodeId = params.nodes[0];
      showNodeDetail(nodeId);
    }} else {{
      document.getElementById('panel-node-detail').style.display = 'none';
      selectedNodeId = null;
    }}
  }});

  network.on('doubleClick', function (params) {{
    if (!params.nodes.length) return;
    const nodeId = params.nodes[0];
    const node = graphNodes.find(function (n) {{ return n.id === nodeId; }});
    if (node && node.username) {{
      doPivot(node.username);
      termLogSemantic('Pivoted identity to: ' + node.username, 'cmd');
    }}
  }});

  network.on('dragEnd', function (params) {{
    if (!params.nodes.length || !nodeData || !network) return;
    try {{
      const pos = network.getPositions(params.nodes);
      params.nodes.forEach(function (id) {{
        if (pos[id]) nodeData.update({{ id: id, x: pos[id].x, y: pos[id].y }});
      }});
    }} catch (e) {{}}
  }});
}}

function centerOnPivot() {{
  if (!network || !graphNodes.length) return false;
  const pivotUser = (state.player || {{}}).pivot || '';
  if (!pivotUser) return false;
  const pivotNode = graphNodes.find(n => n.username && n.username.toLowerCase() === pivotUser.toLowerCase());
  if (!pivotNode) return false;
  network.focus(pivotNode.id, {{ scale: 1.15, animation: {{ duration: 400, easingFunction: 'easeInOutQuad' }} }});
  return true;
}}

function graphFit() {{
  if (!network) return;
  network.fit({{ animation: {{ duration: 300 }}, nodes: nodeData ? nodeData.getIds() : undefined }});
}}

function graphZoom(factor) {{
  if (!network) return;
  const next = Math.max(0.12, Math.min(network.getScale() * factor, 4));
  network.moveTo({{ scale: next, animation: {{ duration: 180 }} }});
}}

/* ── Delegate clicks: postex run + copy-to-clipboard ─────── */
document.addEventListener('click', function(e) {{
  const postexBtn = e.target.closest('.postex-run-btn');
  if (postexBtn) {{
    e.preventDefault();
    e.stopPropagation();
    openPostexModal({{ op: postexBtn.getAttribute('data-postex-op') || '' }});
    return;
  }}
  const target = e.target.closest('[data-copy-val]');
  if (target) {{
    const val = target.getAttribute('data-copy-val');
    const label = target.getAttribute('data-copy-label') || 'Item';
    copyToClipboard(val, label);
  }}
}});

{SHARPHOUND_JS}

{BLOODHOUND_OVERLAY_JS}

{edge_catalog_js}
{playbook_maps_js}
{edge_abuse_js}
{cheatsheet_catalog_js}
{WORKSPACE_VARS_JS}
{WORKSPACE_UI_JS}
{PATH_PLAYBOOK_JS}

{OUTPUT_PARSER_JS}

{CHEATSHEET_JS}

/* ── Init triggers ────────────────────────────────────────── */
disableShellMode();
connectSSE();
refreshState();
initTerminalResize();
document.getElementById('shell-cmd')?.addEventListener('keydown', function (ev) {{
  if (ev.key === 'Enter') {{
    ev.preventDefault();
    sendShellLine();
  }}
}});
if (typeof WorkspaceVars !== 'undefined') {{
  WorkspaceVars.bindTerminalInputs();
}}
if (typeof OutputParser !== 'undefined') OutputParser.init();
if (typeof CheatsheetView !== 'undefined') CheatsheetView.init();
if (typeof OutputParser !== 'undefined') OutputParser.init();
bindWorkspaceModal();
bindHeaderInlineEdit();
termLogSemantic('ADMapper dashboard loaded', 'done');
</script>
{WORKSPACE_MODAL_HTML}
</body>
</html>"""
