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


def _esc(text: Any) -> str:
    return html.escape(str(text or ""))


def build_dashboard_html(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
    api_mode: bool = False,
) -> str:
    """Return the full HTML dashboard SPA."""
    domain_s = _esc(domain or "")
    workspace_s = _esc(workspace)
    pivot_s = _esc(pivot_user or "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ADMapper — {workspace_s}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
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
.filter-group{{display:flex;gap:0.2rem;border-right:1px solid var(--border);padding-right:0.5rem}}
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
  border-radius:6px;padding:0.5rem 0.75rem;font-size:0.65rem;z-index:5;
  display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap;
  backdrop-filter:blur(4px);
}}
.legend-item{{display:flex;align-items:center;gap:0.3rem;white-space:nowrap;font-weight:500}}

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
  transition:height 0.2s;
}}
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
.term-time{{color:var(--text-muted);font-size:0.6rem;margin-right:0.45rem;flex-shrink:0}}
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
</style>
</head>
<body>
<div class="app">

  <!-- ── Header ─────────────────────────────────────────── -->
  <div class="header">
    <span class="logo"><i class="fa-solid fa-network-wired"></i> ADMapper</span>
    <div class="meta">
      <span>Domain: <strong id="h-domain">{domain_s or '...'}</strong></span>
      <span>DC: <strong id="h-dc">...</strong></span>
      <span>Active Pivot: <strong id="h-pivot" style="color:var(--orange)">{pivot_s or 'none'}</strong></span>
    </div>
    <div class="status" id="h-status">
      <span class="dot" style="background:var(--green)"></span> Ready
    </div>
  </div>

  <!-- ── Main Area (Graph Canvas + Panels) ──────────────── -->
  <div class="main">
    <div class="graph-area">
      <!-- Graph header controls and filter bar -->
      <div class="graph-header-controls">
        <div class="filter-group">
          <button class="btn-graph-ctl filter-btn active" data-filter="all" onclick="setGraphFilter('all')" title="Show all discovered nodes"><i class="fa-solid fa-border-all"></i> All</button>
          <button class="btn-graph-ctl filter-btn" data-filter="highvalue" onclick="setGraphFilter('highvalue')" title="Filter: High-Value Targets / Domain Admins"><i class="fa-solid fa-crown"></i> High Value</button>
          <button class="btn-graph-ctl filter-btn" data-filter="compromised" onclick="setGraphFilter('compromised')" title="Filter: Compromised Accounts Only"><i class="fa-solid fa-skull"></i> Compromised</button>
          <button class="btn-graph-ctl filter-btn" data-filter="path" onclick="setGraphFilter('path')" title="Filter: Active Attack Paths Only"><i class="fa-solid fa-road"></i> Attack Path</button>
        </div>
        <div class="graph-controls-group">
          <button class="btn-graph-ctl" onclick="graphFit()" title="Fit all elements in view"><i class="fa-solid fa-expand"></i> Fit</button>
          <button class="btn-graph-ctl" onclick="graphPhysics()" id="btn-physics" title="Toggle force-directed physics layout"><i class="fa-solid fa-wind"></i> Physics: On</button>
          <button class="btn-graph-ctl" onclick="centerOnPivot()" title="Focus view on current pivot identity"><i class="fa-solid fa-crosshairs"></i> Center Pivot</button>
          <button class="btn-graph-ctl" onclick="refreshState()" title="Reload data state"><i class="fa-solid fa-arrows-rotate"></i> Refresh</button>
        </div>
      </div>

      <!-- network canvas -->
      <div id="graph-canvas"></div>

      <!-- network legend -->
      <div class="legend">
        <div class="legend-item" style="color:var(--orange)"><i class="fa-solid fa-star"></i> Pivot</div>
        <div class="legend-item" style="color:var(--green)"><i class="fa-solid fa-circle-check"></i> Compromised</div>
        <div class="legend-item" style="color:var(--red)"><i class="fa-solid fa-crown"></i> High Value/DC</div>
        <div class="legend-item" style="color:#ec4899"><i class="fa-solid fa-key"></i> Kerberoastable</div>
        <div class="legend-item" style="color:#a855f7"><i class="fa-solid fa-unlock"></i> AS-REP Roast</div>
        <div class="legend-item" style="color:var(--purple)"><i class="fa-solid fa-users"></i> AD Group</div>
        <div class="legend-item" style="color:var(--indigo)"><i class="fa-solid fa-desktop"></i> Host/Computer</div>
        <div class="legend-item" style="color:var(--cyan)"><i class="fa-solid fa-user-gear"></i> gMSA</div>
        <div class="legend-item" style="color:#94a3b8"><i class="fa-solid fa-user"></i> Standard User</div>
      </div>
    </div>

    <!-- Right Sidebar Panel -->
    <div class="sidebar">
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

      <!-- Node detail inspector -->
      <div class="panel" id="panel-node-detail" style="display:none;background:var(--bg-card);">
        <div class="panel-header">Selected Object Info</div>
        <div id="node-detail-content"></div>
      </div>
    </div>
  </div>

  <!-- ── Bottom Terminal Area ───────────────────────────── -->
  <div class="terminal-bar" id="terminal-bar" style="height:170px">
    <div class="terminal-header" onclick="toggleTerminal()">
      <span><span class="dot" style="background:var(--green)"></span> Terminal logs</span>
      <span style="display:flex;align-items:center;gap:0.6rem">
        <span id="term-status" style="font-size:0.65rem">waiting for updates...</span>
        <span class="term-actions">
          <button onclick="event.stopPropagation();clearTerminal()" title="Clear Output Log">Clear</button>
          <button id="btn-collapse" onclick="event.stopPropagation();toggleTerminal()">_</button>
        </span>
      </span>
    </div>
    <div class="terminal-output" id="terminal"></div>
    <div class="input-bar">
      <input id="input-ip" placeholder="target subnet / host IP" style="flex:1;max-width:160px"/>
      <button class="btn-graph-ctl" onclick="doDiscovery()" id="btn-scan" style="margin-right:0.6rem;"><i class="fa-solid fa-magnifying-glass"></i> Discovery</button>
      <input id="input-user" placeholder="domain user" style="flex:1;max-width:130px"/>
      <input id="input-pass" placeholder="password" type="password" style="flex:1;max-width:130px"/>
      <button class="btn-graph-ctl btn-primary" onclick="doAuth()" id="btn-auth"><i class="fa-solid fa-key"></i> Authenticate</button>
    </div>
  </div>

</div>

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
let currentGraphFilter = 'all';
let currentSessionPivot = '';

/* ── Terminal Output Logging ──────────────────────────────── */
const term = document.getElementById('terminal');

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
  
  // Extract pivot user tag if present
  const pivotMatch = text.match(/\\[pivot:([^\\]]+)\\]/);
  if (pivotMatch) {{
    const pUser = pivotMatch[1];
    pivotTag = `<span class="pivot-badge-terminal">${{escHtml(pUser)}}</span> `;
    outputText = text.replace(/\\[pivot:[^\\]]+\\]/, '').trim();
    
    // Add visually distinct pivot transition divider
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
  else if (kind === 'error') icon = 'fa-circle-xmark';
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
  term.scrollTop = term.scrollHeight;
  
  // Uncollapse terminal on event stream activity
  document.getElementById('terminal-bar').classList.remove('collapsed');
  const status = document.getElementById('term-status');
  if (status && kind === 'phase') {{
    status.textContent = outputText;
  }} else if (status && (kind === 'done' || kind === 'error')) {{
    status.textContent = kind === 'done' ? 'ready' : 'error';
  }}
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
  termLogSemantic('Terminal output cleared', 'log');
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
      termLogSemantic(d.line || '', d.type || 'log');
      updateStatus(d.type);
    }} catch {{}}
  }};
  es.onerror = () => {{
    setTimeout(connectSSE, 3000);
  }};
}}

function updateStatus(kind) {{
  const el = document.getElementById('h-status');
  if (kind === 'phase') {{
    opRunning = true;
    el.className = 'status';
    el.innerHTML = '<span class="dot" style="background:var(--yellow)"></span> Running';
    setButtonsDisabled(true);
    const status = document.getElementById('term-status');
    if (status) status.textContent = 'running...';
  }} else if (kind === 'done' || kind === 'error') {{
    opRunning = false;
    el.className = 'status';
    el.innerHTML = '<span class="dot" style="background:var(--green)"></span> Ready';
    setButtonsDisabled(false);
    const status = document.getElementById('term-status');
    if (status) status.textContent = kind === 'done' ? 'ready' : 'error';
    setTimeout(refreshState, 600);
  }}
}}

function setButtonsDisabled(disabled) {{
  document.querySelectorAll('#action-buttons-redesign .btn, #btn-auth, #btn-scan').forEach(b => {{
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

function doDiscovery() {{
  const ip = document.getElementById('input-ip').value.trim();
  if (!ip) {{
    termLogSemantic('Please enter a target IP address', 'error');
    return;
  }}
  apiPost('/api/scan', {{ip}});
}}

function doAuth() {{
  const username = document.getElementById('input-user').value.trim();
  const password = document.getElementById('input-pass').value;
  const ip = document.getElementById('input-ip').value.trim();
  if (!username || !password) {{
    termLogSemantic('Please enter username and password credentials', 'error');
    return;
  }}
  const body = {{username, password}};
  if (ip) body.ip = ip;
  apiPost('/api/run', body);
}}

function doExploit() {{ apiPost('/api/exploit'); }}
defAcls = () => apiPost('/api/acls');
function doAcls() {{ apiPost('/api/acls'); }}
function doEnum() {{
  const hasValidCred = (state.creds || []).some(c => String(c.status || '').toLowerCase() === 'valid');
  apiPost('/api/enum', hasValidCred ? {{mode: 'auth'}} : {{}});
}}
function doAsrep() {{ apiPost('/api/asreproast'); }}
function doKerb() {{ apiPost('/api/kerberoast'); }}
function doBrief() {{ apiPost('/api/brief', {{auto: true}}); }}

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
  document.getElementById('h-domain').textContent = meta.domain && meta.domain !== '???' ? meta.domain : '...';
  document.getElementById('h-dc').textContent = meta.dc_host || meta.dc_ip || '...';
  document.getElementById('h-pivot').textContent = (s.player||{{}}).pivot || 'none';

  renderPivotCard(s);
  renderLootPanel(s);
  renderCredentialState(s);
  renderNextBestAction(s);
  renderOperationalPipeline(s);
  renderActionsRedesign(s);
  renderFindingsFeed(s);
  renderGraph(s.graph || {{}});
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
  el.innerHTML = '';
  const creds = s.creds || [];
  const pth = s.pth_sessions || [];
  
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

/* ── Next Best Action (Syntax Highlighted Command) ────────── */
function renderNextBestAction(s) {{
  const el = document.getElementById('next-action-container');
  el.innerHTML = '';
  const obj = s.objective || {{}};
  const progress = s.progress || {{}};
  const creds = s.creds || [];
  const pivot = s.player?.pivot;
  
  let command = 'admapper scan -H <Target_IP>';
  let reason = 'Perform target discovery and unauthenticated service mapping.';
  let impact = 'Discovers domain controllers, SMB signing policies, and LDAP namespaces.';
  
  if (!progress.scan) {{
    command = 'admapper scan -H <Target_IP>';
    reason = 'Perform initial reconnaissance and domain naming context mapping.';
    impact = 'Establishes domain connectivity, checks open AD ports (88, 389, 445), and cache configuration.';
  }} else if (!progress.enum_users) {{
    command = 'admapper enum -w ' + (s.meta?.workspace || 'default');
    reason = 'Perform unauthenticated SAMR/RID user enumeration to extract active domain accounts.';
    impact = 'Maps the domain user account list which serves as the basis for roasting and spray attacks.';
  }} else if (!creds.length) {{
    command = 'admapper asreproast -w ' + (s.meta?.workspace || 'default');
    reason = 'Roast accounts with pre-authentication disabled to obtain crackable hashes.';
    impact = 'Potential cleartext credentials recovery via offline password cracking.';
  }} else if (!pivot) {{
    const firstUser = creds[0]?.user || 'user';
    command = 'admapper run -w ' + (s.meta?.workspace || 'default') + ' -u ' + firstUser + ' -p \\'<password>\\'';
    reason = 'Authenticate with a valid user credential to promote a pivot and unlock LDAP collection.';
    impact = 'Establishes authenticated foothold in the domain to start path auditing.';
  }} else if (obj.command) {{
    command = obj.command;
    reason = obj.headline || 'Execute Active Directory exploitation path.';
    impact = 'Privilege escalation or credential access via Active Directory vulnerability abuse.';
  }}
  
  el.innerHTML = `
    <div class="next-action-card">
      <div style="font-size:0.62rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.3rem;">Active Command Suggestion</div>
      <div class="syntax-code-block" data-copy-val="${{escHtml(command)}}" data-copy-label="Suggested Command" title="Click to copy command">
        <span class="mono">${{highlightCommand(command)}}</span>
        <i class="fa-regular fa-copy copy-icon"></i>
      </div>
      <div style="margin-top:0.45rem;font-size:0.7rem;line-height:1.35;">
        <div style="color:var(--text);margin-bottom:0.15rem;"><strong>Reason:</strong> ${{escHtml(reason)}}</div>
        <div style="color:var(--text-dim);"><strong>Impact:</strong> ${{escHtml(impact)}}</div>
      </div>
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
  const progress = s.progress || {{}};
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
  
  const progress = s.progress || {{}};
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
  if (!pivot) {{
    el.innerHTML = '<div class="nd-empty">No active pivot established</div>';
    return;
  }}
  const initial = pivot.charAt(0).toUpperCase();
  const domain = meta.domain && meta.domain !== '???' ? meta.domain : '';
  el.innerHTML = `
    <div class="pivot-card">
      <div class="avatar">${{escHtml(initial)}}</div>
      <div class="info">
        <div class="name">${{escHtml(pivot)}}</div>
        <div class="detail">${{domain ? escHtml(domain) + ' &middot; ' : ''}}Pivot Foothold</div>
      </div>
    </div>
  `;
}}

/* ── vis-network Graph Redesign & Controls ────────────────── */
function renderGraph(graphData) {{
  if (!graphData.nodes || !graphData.nodes.length) return;

  const pivotUser = (state.player || {{}}).pivot || '';

  graphNodes = graphData.nodes.map(n => {{
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
      font: {{ color: '#c9d1d9', size: isPivot ? 12 : (isDC ? 11 : 9), strokeWidth: 2, strokeColor: '#0d1117' }},
    }};
  }});

  graphEdges = graphData.edges.map(e => {{
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
      smooth: {{ type: 'dynamic' }},
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

  setGraphFilter(currentGraphFilter);
}}

function setGraphFilter(filter) {{
  currentGraphFilter = filter;
  document.querySelectorAll('.filter-btn').forEach(btn => {{
    btn.classList.toggle('active', btn.dataset.filter === filter);
  }});
  
  if (!network && !graphNodes.length) return;
  
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

  const networkData = {{
    nodes: new vis.DataSet(filteredNodes),
    edges: new vis.DataSet(filteredEdges)
  }};

  if (network) {{
    network.setData(networkData);
    nodeData = networkData.nodes;
    edgeData = networkData.edges;
    return;
  }}

  const graphArea = container.parentElement;
  container.style.width = graphArea.clientWidth + 'px';
  container.style.height = graphArea.clientHeight + 'px';

  network = new vis.Network(container, networkData, {{
    width: '100%',
    height: '100%',
    autoResize: true,
    physics: {{
      stabilization: {{ iterations: 200, updateInterval: 25 }},
      barnesHut: {{ gravitationalConstant: -5000, springLength: 150, springConstant: 0.04 }},
    }},
    interaction: {{
      hover: true,
      tooltipDelay: 200,
      zoomView: true,
      dragView: true,
    }},
    edges: {{
      arrows: {{ to: {{ enabled: true, scaleFactor: 0.6 }} }},
      smooth: {{ type: 'dynamic' }},
    }},
  }});
  
  nodeData = networkData.nodes;
  edgeData = networkData.edges;

  network.once('stabilizationIterationsDone', () => {{
    network.setOptions({{ physics: false }});
    physicsOn = false;
    document.getElementById('btn-physics').innerHTML = '<i class="fa-solid fa-wind"></i> Physics: Off';
    centerOnPivot() || network.fit();
  }});

  const ro = new ResizeObserver(() => {{
    if (network) {{ network.redraw(); }}
  }});
  ro.observe(graphArea);

  network.on('click', (params) => {{
    if (params.nodes.length) {{
      const nodeId = params.nodes[0];
      showNodeDetail(nodeId);
      const node = graphNodes.find(n => n.id === nodeId);
      if (node && node.username) {{
        const isOwned = node.identity_role === 'owned' || node.identity_role === 'pivot' || 
                        (state.player && state.player.owned && state.player.owned.map(u => u.toLowerCase()).includes(node.username.toLowerCase()));
        if (isOwned && node.username.toLowerCase() !== ((state.player || {{}}).pivot || '').toLowerCase()) {{
          doPivot(node.username);
        }}
      }}
    }} else {{
      document.getElementById('panel-node-detail').style.display = 'none';
      selectedNodeId = null;
    }}
  }});

  network.on('doubleClick', (params) => {{
    if (params.nodes.length) {{
      const nodeId = params.nodes[0];
      const node = graphNodes.find(n => n.id === nodeId);
      if (node && node.username) {{
        doPivot(node.username);
        termLogSemantic('Pivoted identity to: ' + node.username, 'cmd');
      }}
    }}
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

function graphFit() {{ if (network) network.fit({{ animation: true }}); }}

function graphPhysics() {{
  physicsOn = !physicsOn;
  if (network) network.setOptions({{ physics: physicsOn }});
  document.getElementById('btn-physics').innerHTML = '<i class="fa-solid fa-wind"></i> Physics: ' + (physicsOn ? 'On' : 'Off');
}}

/* ── Delegate click-to-copy handler ───────────────────────── */
document.addEventListener('click', function(e) {{
  const target = e.target.closest('[data-copy-val]');
  if (target) {{
    const val = target.getAttribute('data-copy-val');
    const label = target.getAttribute('data-copy-label') || 'Item';
    copyToClipboard(val, label);
  }}
}});

/* ── Init triggers ────────────────────────────────────────── */
connectSSE();
refreshState();
termLogSemantic('ADMapper dashboard loaded', 'done');
</script>
</body>
</html>"""
