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
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
/* ── Reset & Base ─────────────────────────────────────────── */
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg-dark:#0a0e1a;--bg-panel:#111827;--bg-card:#1e293b;--bg-hover:#334155;
  --border:#1e293b;--border-light:#334155;
  --text:#e2e8f0;--text-dim:#94a3b8;--text-muted:#64748b;
  --accent:#3b82f6;--accent-glow:#60a5fa;
  --green:#22c55e;--orange:#f97316;--red:#ef4444;--cyan:#06b6d4;
  --purple:#8b5cf6;--yellow:#eab308;--indigo:#6366f1;
  --font:'Segoe UI',system-ui,-apple-system,sans-serif;
  --mono:'JetBrains Mono','Fira Code','Cascadia Code',monospace;
}}
html,body{{height:100%;overflow:hidden;font-family:var(--font);background:var(--bg-dark);color:var(--text)}}
::-webkit-scrollbar{{width:6px}}
::-webkit-scrollbar-track{{background:var(--bg-panel)}}
::-webkit-scrollbar-thumb{{background:var(--border-light);border-radius:3px}}

/* ── Layout ───────────────────────────────────────────────── */
.app{{display:flex;flex-direction:column;height:100vh;overflow:hidden}}
.header{{
  display:flex;align-items:center;gap:0.75rem;flex-shrink:0;
  padding:0.4rem 1rem;background:var(--bg-panel);border-bottom:1px solid var(--border);
  z-index:10;
}}
.header .logo{{font-weight:700;font-size:1.1rem;color:var(--accent-glow);letter-spacing:-0.02em}}
.header .meta{{color:var(--text-dim);font-size:0.78rem;display:flex;gap:0.75rem;flex:1;flex-wrap:wrap}}
.header .meta span{{display:flex;align-items:center;gap:0.25rem}}
.header .meta strong{{color:var(--text);font-weight:500}}
.header .status{{
  display:flex;align-items:center;gap:0.4rem;font-size:0.72rem;
  padding:0.2rem 0.55rem;border-radius:999px;white-space:nowrap;
}}
.status-idle{{background:#14532d;color:#86efac}}
.status-running{{background:#713f12;color:#fde68a}}

.main{{display:grid;grid-template-columns:1fr 300px;grid-template-rows:1fr;flex:1;min-height:0;overflow:hidden}}
.graph-area{{position:relative;background:var(--bg-dark);overflow:hidden;min-height:350px;flex:1}}
#graph-canvas{{position:absolute;top:0;left:0;right:0;bottom:0}}
.graph-controls{{
  position:absolute;top:0.6rem;left:0.6rem;display:flex;gap:0.3rem;z-index:5;
}}
.graph-controls button{{
  background:var(--bg-card);border:1px solid var(--border-light);color:var(--text);
  padding:0.25rem 0.5rem;border-radius:4px;font-size:0.7rem;cursor:pointer;
}}
.graph-controls button:hover{{background:var(--bg-hover)}}

/* Legend overlay */
.legend{{
  position:absolute;bottom:0.6rem;left:0.6rem;
  background:rgba(17,24,39,0.9);border:1px solid var(--border-light);
  border-radius:6px;padding:0.4rem 0.6rem;font-size:0.65rem;z-index:5;
  display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;
}}
.legend-item{{display:flex;align-items:center;gap:0.2rem;white-space:nowrap}}
.legend-dot{{width:8px;height:8px;border-radius:2px;flex-shrink:0}}

/* ── Right Sidebar ────────────────────────────────────────── */
.sidebar{{
  background:var(--bg-panel);border-left:1px solid var(--border);
  overflow-y:auto;display:flex;flex-direction:column;
}}
.panel{{border-bottom:1px solid var(--border);padding:0.6rem 0.65rem}}
.panel-header{{
  font-size:0.68rem;text-transform:uppercase;letter-spacing:0.06em;
  color:var(--text-muted);font-weight:600;margin-bottom:0.4rem;
  display:flex;justify-content:space-between;align-items:center;
}}
.panel-count{{
  background:var(--bg-card);padding:0.1rem 0.4rem;border-radius:999px;
  font-size:0.62rem;color:var(--text-dim);
}}

/* Pivot identity card */
.pivot-card{{
  background:linear-gradient(135deg,#1e293b 0%,#172033 100%);
  border-radius:6px;padding:0.55rem 0.65rem;
  border:1px solid var(--orange);
  display:flex;align-items:center;gap:0.5rem;
}}
.pivot-card .avatar{{
  width:32px;height:32px;border-radius:50%;
  background:var(--orange);display:flex;align-items:center;justify-content:center;
  font-weight:700;font-size:0.8rem;color:#fff;flex-shrink:0;
}}
.pivot-card .info .name{{font-weight:600;font-size:0.82rem;color:var(--orange)}}
.pivot-card .info .detail{{font-size:0.68rem;color:var(--text-dim)}}

/* Node detail */
.node-detail{{
  background:var(--bg-card);border-radius:6px;padding:0.55rem 0.65rem;
  border:1px solid var(--border-light);
}}
.node-detail .nd-name{{font-weight:600;font-size:0.82rem;margin-bottom:0.3rem}}
.node-detail .nd-type{{font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.3rem}}
.node-detail .nd-row{{font-size:0.7rem;color:var(--text-dim);margin-bottom:0.15rem;display:flex;justify-content:space-between}}
.node-detail .nd-row strong{{color:var(--text);font-weight:500}}
.node-detail .nd-edges{{margin-top:0.35rem;max-height:100px;overflow-y:auto}}
.node-detail .nd-edge{{font-size:0.65rem;color:var(--text-dim);padding:0.1rem 0}}
.nd-empty{{font-size:0.7rem;color:var(--text-muted);font-style:italic}}

/* Phase bar */
.phases{{display:flex;gap:2px;margin-bottom:0.2rem}}
.phase{{
  flex:1;height:3px;border-radius:2px;background:var(--border-light);
  position:relative;
}}
.phase.done{{background:var(--green)}}
.phase.partial{{background:var(--yellow)}}
.phase-labels{{display:flex;justify-content:space-between;font-size:0.58rem;color:var(--text-muted)}}

/* Action buttons */
.action-group{{margin-bottom:0.35rem}}
.action-group-label{{font-size:0.6rem;color:var(--text-muted);margin-bottom:0.2rem;text-transform:uppercase;letter-spacing:0.05em}}
.actions{{display:flex;flex-wrap:wrap;gap:0.25rem}}
.btn{{
  padding:0.25rem 0.5rem;border-radius:4px;font-size:0.7rem;font-weight:500;
  cursor:pointer;border:1px solid var(--border-light);background:var(--bg-card);
  color:var(--text);transition:all 0.15s;
}}
.btn:hover:not(:disabled){{background:var(--bg-hover);border-color:var(--accent)}}
.btn:disabled{{opacity:0.35;cursor:not-allowed}}
.btn-primary{{background:var(--accent);border-color:var(--accent);color:#fff}}
.btn-primary:hover:not(:disabled){{background:#2563eb}}
.btn-danger{{border-color:var(--red);color:var(--red)}}
.btn-danger:hover:not(:disabled){{background:rgba(239,68,68,0.15)}}

/* Findings list */
.finding{{
  padding:0.35rem 0.5rem;margin-bottom:0.25rem;border-radius:4px;
  background:var(--bg-card);border-left:3px solid var(--text-muted);
  font-size:0.72rem;
}}
.finding.critical{{border-color:var(--red)}}
.finding.high{{border-color:var(--orange)}}
.finding.medium{{border-color:var(--yellow)}}
.finding .title{{font-weight:500;margin-bottom:0.1rem}}
.finding .detail{{color:var(--text-dim);font-size:0.66rem}}

/* Credential rows */
.cred-row{{
  display:flex;justify-content:space-between;align-items:center;
  padding:0.25rem 0.4rem;margin-bottom:0.15rem;border-radius:3px;
  background:var(--bg-card);font-size:0.72rem;cursor:pointer;
  transition:background 0.1s;
}}
.cred-row:hover{{background:var(--bg-hover)}}
.cred-row .user{{font-weight:500}}
.cred-row .badge{{
  padding:0.08rem 0.3rem;border-radius:3px;font-size:0.6rem;font-weight:600;
}}
.badge-valid{{background:#14532d;color:#86efac}}
.badge-hash{{background:#312e81;color:#a5b4fc}}

/* ── Bottom Terminal ──────────────────────────────────────── */
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
  padding:0.25rem 0.65rem;font-size:0.68rem;color:var(--text-muted);
  border-bottom:1px solid var(--border);flex-shrink:0;cursor:pointer;
}}
.terminal-header:hover{{background:var(--bg-hover)}}
.terminal-header .dot{{width:6px;height:6px;border-radius:50%;margin-right:0.25rem}}
.terminal-header .term-actions{{display:flex;gap:0.3rem}}
.terminal-header .term-actions button{{
  background:none;border:none;color:var(--text-muted);cursor:pointer;
  font-size:0.65rem;padding:0.1rem 0.3rem;border-radius:3px;
}}
.terminal-header .term-actions button:hover{{color:var(--text);background:var(--bg-card)}}
.terminal-output{{
  flex:1;overflow-y:auto;padding:0.35rem 0.65rem;
  font-family:var(--mono);font-size:0.7rem;line-height:1.5;
}}
.term-line{{white-space:pre-wrap;word-break:break-all}}
.term-cmd{{color:var(--accent-glow);font-weight:600}}
.term-done{{color:var(--green)}}
.term-error{{color:var(--red)}}
.term-phase{{color:var(--cyan);font-weight:500}}
.term-log{{color:var(--text-dim)}}
.term-time{{color:var(--text-muted);font-size:0.58rem;margin-right:0.35rem}}

/* ── Input bar ────────────────────────────────────────────── */
.input-bar{{
  display:flex;gap:0.35rem;padding:0.3rem 0.65rem;
  border-top:1px solid var(--border);background:var(--bg-card);flex-shrink:0;
  flex-wrap:wrap;
}}
.input-bar input{{
  background:var(--bg-dark);border:1px solid var(--border-light);
  color:var(--text);padding:0.25rem 0.4rem;border-radius:4px;
  font-family:var(--mono);font-size:0.7rem;outline:none;min-width:0;
}}
.input-bar input:focus{{border-color:var(--accent)}}
.input-bar input::placeholder{{color:var(--text-muted)}}

/* ── Spray inline input ───────────────────────────────────── */
.spray-inline{{display:flex;gap:0.25rem;align-items:center}}
.spray-inline input{{
  background:var(--bg-dark);border:1px solid var(--border-light);
  color:var(--text);padding:0.2rem 0.35rem;border-radius:3px;
  font-size:0.68rem;width:90px;outline:none;
}}
.spray-inline input:focus{{border-color:var(--accent)}}

/* ── vis-network tooltip ──────────────────────────────────── */
.vis-tooltip{{
  background:var(--bg-card)!important;color:var(--text)!important;
  border:1px solid var(--border-light)!important;border-radius:6px!important;
  padding:0.4rem 0.6rem!important;font-size:0.72rem!important;
  font-family:var(--mono)!important;max-width:350px!important;
  box-shadow:0 4px 12px rgba(0,0,0,0.4)!important;
}}

/* ── Responsive ───────────────────────────────────────────── */
@media(max-width:900px){{
  .main{{display:flex;flex-direction:column;min-height:0}}
  .graph-area{{min-height:350px;flex:1 1 55%}}
  .sidebar{{border-left:none;border-top:1px solid var(--border);overflow-y:auto;max-height:45vh}}
}}

/* ── Pulse animation for pivot node ───────────────────────── */
@keyframes pulse{{0%{{box-shadow:0 0 0 0 rgba(249,115,22,0.4)}}70%{{box-shadow:0 0 0 8px rgba(249,115,22,0)}}100%{{box-shadow:0 0 0 0 rgba(249,115,22,0)}}}}
</style>
</head>
<body>
<div class="app">

  <!-- ── Header ─────────────────────────────────────────── -->
  <div class="header">
    <span class="logo">ADMapper</span>
    <div class="meta">
      <span>Domain: <strong id="h-domain">{domain_s or '...'}</strong></span>
      <span>DC: <strong id="h-dc">...</strong></span>
      <span>Pivot: <strong id="h-pivot" style="color:var(--orange)">{pivot_s or 'none'}</strong></span>
    </div>
    <div class="status status-idle" id="h-status">
      <span class="dot" style="background:var(--green)"></span> Ready
    </div>
  </div>

  <!-- ── Main: Graph + Sidebar ──────────────────────────── -->
  <div class="main">
    <div class="graph-area">
      <div class="graph-controls">
        <button onclick="graphFit()" title="Fit to viewport">Fit</button>
        <button onclick="graphPhysics()" id="btn-physics" title="Toggle physics simulation">Physics</button>
        <button onclick="centerOnPivot()" title="Center on pivot user">Center</button>
        <button onclick="refreshState()" title="Refresh data">Refresh</button>
      </div>
      <div id="graph-canvas"></div>
      <div class="legend">
        <div class="legend-item"><span class="legend-dot" style="background:var(--orange);border-radius:50%"></span>Pivot</div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--green)"></span>Owned</div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--red)"></span>High-Value</div>
        <div class="legend-item"><span class="legend-dot" style="background:#ec4899"></span>Kerberoastable</div>
        <div class="legend-item"><span class="legend-dot" style="background:#a855f7"></span>AS-REP Roastable</div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--purple)"></span>Group</div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--indigo)"></span>Computer</div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--cyan)"></span>gMSA</div>
        <div class="legend-item"><span class="legend-dot" style="background:#475569"></span>User</div>
      </div>
    </div>

    <div class="sidebar">
      <!-- Current Identity / Pivot -->
      <div class="panel" id="panel-pivot">
        <div class="panel-header">Current Identity</div>
        <div id="pivot-display">
          <div class="nd-empty">No pivot user set</div>
        </div>
      </div>

      <!-- Node Detail (populated on click) -->
      <div class="panel" id="panel-node-detail" style="display:none">
        <div class="panel-header">Node Detail</div>
        <div id="node-detail-content"></div>
      </div>

      <!-- Phases -->
      <div class="panel">
        <div class="panel-header">Attack Chain <span class="panel-count" id="phase-count">0/12</span></div>
        <div class="phases" id="phase-bar"></div>
        <div class="phase-labels"><span>Recon</span><span>Attack</span><span>Post</span></div>
      </div>

      <!-- Actions — grouped -->
      <div class="panel" id="panel-actions">
        <div class="panel-header">Actions</div>
        <div id="action-buttons"></div>
      </div>

      <!-- Credentials -->
      <div class="panel">
        <div class="panel-header">Credentials <span class="panel-count" id="cred-count">0</span></div>
        <div id="cred-list"></div>
      </div>

      <!-- Hashes / PTH -->
      <div class="panel" id="panel-hashes" style="display:none">
        <div class="panel-header">NT Hashes <span class="panel-count" id="hash-count">0</span></div>
        <div id="hash-list"></div>
      </div>

      <!-- Attack Paths -->
      <div class="panel">
        <div class="panel-header">Attack Paths <span class="panel-count" id="path-count">0</span></div>
        <div id="path-list"></div>
      </div>

      <!-- Findings -->
      <div class="panel">
        <div class="panel-header">Findings <span class="panel-count" id="finding-count">0</span></div>
        <div id="finding-list"></div>
      </div>
    </div>
  </div>

  <!-- ── Terminal ───────────────────────────────────────── -->
  <div class="terminal-bar" id="terminal-bar" style="height:160px">
    <div class="terminal-header" onclick="toggleTerminal()">
      <span><span class="dot" style="background:var(--green)"></span> Terminal</span>
      <span style="display:flex;align-items:center;gap:0.5rem">
        <span id="term-status" style="font-size:0.62rem">waiting for events...</span>
        <span class="term-actions">
          <button onclick="event.stopPropagation();clearTerminal()" title="Clear">Clear</button>
          <button id="btn-collapse" onclick="event.stopPropagation();toggleTerminal()">_</button>
        </span>
      </span>
    </div>
    <div class="terminal-output" id="terminal"></div>
    <div class="input-bar">
      <input id="input-user" placeholder="username" style="flex:1;max-width:130px"/>
      <input id="input-pass" placeholder="password" type="password" style="flex:1;max-width:140px"/>
      <button class="btn btn-primary" onclick="doAuth()" id="btn-auth">Authenticate</button>
      <input id="input-ip" placeholder="target IP" style="flex:1;max-width:120px"/>
      <button class="btn" onclick="doScan()" id="btn-scan">Scan</button>
    </div>
  </div>

</div>

<script>
/* ── State ────────────────────────────────────────────────── */
let state = {{}};
let network = null;
let physicsOn = true;
let opRunning = false;
let selectedNodeId = null;
let graphNodes = [];
let graphEdges = [];

/* ── SSE live events ──────────────────────────────────────── */
const term = document.getElementById('terminal');
function termLog(text, kind) {{
  const el = document.createElement('div');
  el.className = 'term-line term-' + (kind || 'log');
  const now = new Date();
  const ts = String(now.getHours()).padStart(2,'0') + ':' +
             String(now.getMinutes()).padStart(2,'0') + ':' +
             String(now.getSeconds()).padStart(2,'0');
  el.innerHTML = '<span class="term-time">' + ts + '</span>' + escHtml(text);
  term.appendChild(el);
  term.scrollTop = term.scrollHeight;
  /* Uncollapse terminal when new events arrive */
  document.getElementById('terminal-bar').classList.remove('collapsed');
}}

function escHtml(s) {{
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}}

function clearTerminal() {{
  term.innerHTML = '';
  termLog('Terminal cleared', 'log');
}}

function toggleTerminal() {{
  const tb = document.getElementById('terminal-bar');
  tb.classList.toggle('collapsed');
  document.getElementById('btn-collapse').textContent = tb.classList.contains('collapsed') ? '+' : '_';
}}

function connectSSE() {{
  const es = new EventSource('/api/events');
  es.onmessage = (e) => {{
    try {{
      const d = JSON.parse(e.data);
      if (d.type === 'state') {{
        try {{ const inner = JSON.parse(d.line); if (inner.refresh) refreshState(); }} catch {{}}
        return;
      }}
      termLog(d.line || '', d.type || 'log');
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
    el.className = 'status status-running';
    el.innerHTML = '<span class="dot" style="background:var(--yellow)"></span> Running';
    setButtonsDisabled(true);
  }} else if (kind === 'done' || kind === 'error') {{
    opRunning = false;
    el.className = 'status status-idle';
    el.innerHTML = '<span class="dot" style="background:var(--green)"></span> Ready';
    setButtonsDisabled(false);
    setTimeout(refreshState, 500);
  }}
}}

function setButtonsDisabled(disabled) {{
  document.querySelectorAll('#action-buttons .btn, #btn-auth, #btn-scan').forEach(b => {{
    b.disabled = disabled;
  }});
}}

/* ── API calls ────────────────────────────────────────────── */
function apiPost(path, body) {{
  return fetch(path, {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify(body || {{}}),
  }});
}}

function doScan() {{
  const ip = document.getElementById('input-ip').value.trim();
  if (!ip) return;
  apiPost('/api/scan', {{ip}});
}}

function doAuth() {{
  const username = document.getElementById('input-user').value.trim();
  const password = document.getElementById('input-pass').value;
  if (!username || !password) return;
  apiPost('/api/run', {{username, password}});
}}

function doExploit() {{ apiPost('/api/exploit'); }}
function doAcls() {{ apiPost('/api/acls'); }}
function doEnum() {{ apiPost('/api/enum'); }}
function doAsrep() {{ apiPost('/api/asreproast'); }}
function doKerb() {{ apiPost('/api/kerberoast'); }}
function doBrief() {{ apiPost('/api/brief', {{auto: true}}); }}

function doSpray() {{
  const input = document.getElementById('spray-pw');
  if (!input) return;
  const pw = input.value.trim();
  if (!pw) {{ input.focus(); return; }}
  apiPost('/api/spray', {{password: pw}});
  input.value = '';
}}

function doPivot(username) {{
  apiPost('/api/pivot', {{username}}).then(r => r.json()).then(d => {{
    if (d.state) renderState(d.state);
  }});
}}

/* ── State refresh ────────────────────────────────────────── */
async function refreshState() {{
  try {{
    const r = await fetch('/api/state');
    state = await r.json();
    renderState(state);
  }} catch {{}}
}}

/* ── Render state ─────────────────────────────────────────── */
function renderState(s) {{
  state = s;
  const meta = s.meta || {{}};
  document.getElementById('h-domain').textContent = meta.domain && meta.domain !== '???' ? meta.domain : '...';
  document.getElementById('h-dc').textContent = meta.dc_host || meta.dc_ip || '...';
  document.getElementById('h-pivot').textContent = (s.player||{{}}).pivot || 'none';

  renderPivotCard(s);
  renderPhases(s.phases || []);
  renderActions(s);
  renderCredentials(s.creds || [], s.pth_sessions || []);
  renderHashes(s.pth_sessions || []);
  renderPaths(s.quests || [], s.objective || {{}});
  renderFindings(s.findings || {{}}, s.highlights || [], s.engagement_intel || {{}});
  renderGraph(s.graph || {{}});
}}

/* ── Pivot Card ───────────────────────────────────────────── */
function renderPivotCard(s) {{
  const el = document.getElementById('pivot-display');
  const pivot = (s.player || {{}}).pivot;
  const meta = s.meta || {{}};
  if (!pivot) {{
    el.innerHTML = '<div class="nd-empty">Authenticate to set a pivot user</div>';
    return;
  }}
  const initial = pivot.charAt(0).toUpperCase();
  const domain = meta.domain && meta.domain !== '???' ? meta.domain : '';
  el.innerHTML =
    '<div class="pivot-card">' +
      '<div class="avatar">' + escHtml(initial) + '</div>' +
      '<div class="info">' +
        '<div class="name">' + escHtml(pivot) + '</div>' +
        '<div class="detail">' +
          (domain ? escHtml(domain) + ' &middot; ' : '') +
          'Pivot User' +
        '</div>' +
      '</div>' +
    '</div>';
}}

/* ── Node Detail (sidebar, on graph click) ────────────────── */
function showNodeDetail(nodeId) {{
  const panel = document.getElementById('panel-node-detail');
  const content = document.getElementById('node-detail-content');
  const node = graphNodes.find(n => n.id === nodeId);
  if (!node) {{ panel.style.display = 'none'; return; }}

  panel.style.display = '';
  selectedNodeId = nodeId;

  const typeMap = {{
    dc: 'Domain Controller', operator: 'Pivot User', user: 'User',
    computer: 'Computer', group: 'Group', gmsa: 'gMSA Account',
    domain: 'Domain', highvalue: 'High-Value Target'
  }};
  const nodeType = typeMap[node.group] || node.group || 'Unknown';

  /* Find connected edges */
  const inEdges = graphEdges.filter(e => e.to === nodeId);
  const outEdges = graphEdges.filter(e => e.from === nodeId);

  let html = '<div class="node-detail">';
  html += '<div class="nd-type">' + escHtml(nodeType) + '</div>';
  html += '<div class="nd-name">' + escHtml(node.label || node.username || node.id) + '</div>';

  if (node.username) {{
    html += '<div class="nd-row"><span>Username</span><strong>' + escHtml(node.username) + '</strong></div>';
  }}
  if (node.title) {{
    html += '<div class="nd-row" style="flex-direction:column;gap:0.1rem"><span style="color:var(--text-muted)">Properties</span>';
    html += '<span style="font-size:0.65rem;color:var(--text-dim);white-space:pre-wrap">' + node.title + '</span></div>';
  }}

  /* Inbound relationships */
  if (inEdges.length) {{
    html += '<div class="nd-edges"><div style="font-size:0.62rem;color:var(--text-muted);margin-bottom:0.15rem">Inbound (' + inEdges.length + ')</div>';
    inEdges.slice(0, 10).forEach(e => {{
      const src = graphNodes.find(n => n.id === e.from);
      html += '<div class="nd-edge">' + escHtml(src?.label || e.from) + ' &rarr; ' + escHtml(e.label || 'MemberOf') + '</div>';
    }});
    if (inEdges.length > 10) html += '<div class="nd-edge" style="color:var(--text-muted)">... +' + (inEdges.length-10) + ' more</div>';
    html += '</div>';
  }}

  /* Outbound relationships */
  if (outEdges.length) {{
    html += '<div class="nd-edges"><div style="font-size:0.62rem;color:var(--text-muted);margin-bottom:0.15rem">Outbound (' + outEdges.length + ')</div>';
    outEdges.slice(0, 10).forEach(e => {{
      const tgt = graphNodes.find(n => n.id === e.to);
      html += '<div class="nd-edge">' + escHtml(e.label || 'MemberOf') + ' &rarr; ' + escHtml(tgt?.label || e.to) + '</div>';
    }});
    if (outEdges.length > 10) html += '<div class="nd-edge" style="color:var(--text-muted)">... +' + (outEdges.length-10) + ' more</div>';
    html += '</div>';
  }}

  if (!inEdges.length && !outEdges.length) {{
    html += '<div class="nd-empty">No relationships</div>';
  }}

  html += '</div>';
  content.innerHTML = html;

  /* Highlight in graph */
  if (network) {{
    network.selectNodes([nodeId], true);
  }}
}}

/* ── Phases ────────────────────────────────────────────────── */
function renderPhases(phases) {{
  const bar = document.getElementById('phase-bar');
  bar.innerHTML = '';
  let done = 0;
  phases.forEach(p => {{
    const el = document.createElement('div');
    el.className = 'phase' + (p.done ? ' done' : (p.partial ? ' partial' : ''));
    el.title = p.label || '';
    bar.appendChild(el);
    if (p.done) done++;
  }});
  document.getElementById('phase-count').textContent = done + '/' + phases.length;
}}

/* ── Actions (grouped) ────────────────────────────────────── */
function renderActions(s) {{
  const container = document.getElementById('action-buttons');
  container.innerHTML = '';
  const progress = s.progress || {{}};
  const hasCreds = (s.creds || []).length > 0;

  /* Recon group */
  const reconGroup = document.createElement('div');
  reconGroup.className = 'action-group';
  reconGroup.innerHTML = '<div class="action-group-label">Reconnaissance</div><div class="actions" id="recon-btns"></div>';
  container.appendChild(reconGroup);

  const reconBtns = reconGroup.querySelector('#recon-btns');
  addBtn(reconBtns, 'Enum Users', 'doEnum()', true);
  addBtn(reconBtns, 'AS-REP Roast', 'doAsrep()', true);
  addBtn(reconBtns, 'Kerberoast', 'doKerb()', true);
  addBtn(reconBtns, 'ACLs', 'doAcls()', progress.scan);

  /* Attack group */
  if (progress.scan || hasCreds) {{
    const atkGroup = document.createElement('div');
    atkGroup.className = 'action-group';
    atkGroup.innerHTML = '<div class="action-group-label">Attack</div><div class="actions" id="atk-btns"></div>';
    container.appendChild(atkGroup);

    const atkBtns = atkGroup.querySelector('#atk-btns');
    addBtn(atkBtns, 'Exploit', 'doExploit()', progress.scan);

    /* Spray with inline input */
    const sprayWrap = document.createElement('div');
    sprayWrap.className = 'spray-inline';
    sprayWrap.innerHTML = '<input id="spray-pw" placeholder="password" style="font-family:var(--mono)"/>';
    const sprayBtn = document.createElement('button');
    sprayBtn.className = 'btn';
    sprayBtn.textContent = 'Spray';
    sprayBtn.onclick = doSpray;
    sprayWrap.appendChild(sprayBtn);
    atkBtns.appendChild(sprayWrap);
  }}

  /* Report group */
  if (progress.exploit) {{
    const repGroup = document.createElement('div');
    repGroup.className = 'action-group';
    repGroup.innerHTML = '<div class="action-group-label">Report</div><div class="actions" id="rep-btns"></div>';
    container.appendChild(repGroup);
    addBtn(repGroup.querySelector('#rep-btns'), 'Generate Brief', 'doBrief()', true);
  }}
}}

function addBtn(container, label, fn, show) {{
  if (!show) return;
  const el = document.createElement('button');
  el.className = 'btn';
  el.textContent = label;
  el.setAttribute('onclick', fn);
  if (opRunning) el.disabled = true;
  container.appendChild(el);
}}

/* ── Credentials ──────────────────────────────────────────── */
function renderCredentials(creds, pth) {{
  const el = document.getElementById('cred-list');
  el.innerHTML = '';
  const total = creds.length + pth.length;
  document.getElementById('cred-count').textContent = total;
  if (!total) {{
    el.innerHTML = '<div class="nd-empty">No credentials yet</div>';
    return;
  }}
  creds.forEach(c => {{
    const row = document.createElement('div');
    row.className = 'cred-row';
    row.innerHTML = '<span class="user">' + escHtml(c.user) + '</span>' +
      '<span class="badge badge-valid">' + escHtml(c.status) + '</span>';
    row.onclick = () => doPivot(c.user);
    row.title = 'Click to pivot to ' + c.user;
    el.appendChild(row);
  }});
}}

/* ── Hashes ────────────────────────────────────────────────── */
function renderHashes(pth) {{
  const panel = document.getElementById('panel-hashes');
  const el = document.getElementById('hash-list');
  document.getElementById('hash-count').textContent = pth.length;
  if (!pth.length) {{ panel.style.display = 'none'; return; }}
  panel.style.display = '';
  el.innerHTML = '';
  pth.forEach(h => {{
    const row = document.createElement('div');
    row.className = 'cred-row';
    row.innerHTML = '<span class="user">' + escHtml(h.account) + '</span>' +
      '<span class="badge badge-hash">NT</span>';
    row.title = h.winrm_cmd || h.nthash || 'Click to copy';
    row.onclick = () => {{
      const text = h.winrm_cmd || h.nthash || '';
      if (text) {{
        navigator.clipboard.writeText(text);
        termLog('Copied: ' + text, 'done');
      }}
    }};
    el.appendChild(row);
  }});
}}

/* ── Attack Paths ─────────────────────────────────────────── */
function renderPaths(quests, objective) {{
  const el = document.getElementById('path-list');
  el.innerHTML = '';
  const ready = quests.filter(q => q.ready || q.verified);
  document.getElementById('path-count').textContent = ready.length;
  if (objective.headline) {{
    const ob = document.createElement('div');
    ob.className = 'finding high';
    ob.innerHTML = '<div class="title">' + escHtml(objective.headline) + '</div>' +
      (objective.command ? '<div class="detail"><code>' + escHtml(objective.command) + '</code></div>' : '');
    ob.style.cursor = 'pointer';
    ob.onclick = () => {{
      if (objective.command) {{
        navigator.clipboard.writeText(objective.command);
        termLog('Copied: ' + objective.command, 'done');
      }}
    }};
    el.appendChild(ob);
  }}
  ready.forEach(q => {{
    const f = document.createElement('div');
    f.className = 'finding ' + (q.severity || 'medium');
    f.innerHTML = '<div class="title">' + escHtml(q.title) + '</div>' +
      '<div class="detail">' + escHtml(q.technique || '') + ' &rarr; ' + escHtml(q.target || '') + '</div>';
    if (q.ready && !opRunning) {{
      f.style.cursor = 'pointer';
      f.onclick = () => apiPost('/api/exploit');
    }}
    el.appendChild(f);
  }});
  if (!ready.length && !objective.headline) {{
    el.innerHTML = '<div class="nd-empty">Run ACLs to discover paths</div>';
  }}
}}

/* ── Findings ─────────────────────────────────────────────── */
function renderFindings(findingsData, highlights, intel) {{
  const el = document.getElementById('finding-list');
  el.innerHTML = '';
  const items = [];

  const rawFindings = (findingsData.findings || findingsData.finding || []);
  rawFindings.forEach(f => {{
    const title = f.title || f.highlight || f.key || '';
    if (!title) return;
    let severity = (f.severity || 'medium').toLowerCase();
    items.push({{title: title + (f.detail ? ' — ' + f.detail : ''), severity: severity}});
  }});

  highlights.forEach(h => items.push({{title: h, severity: 'medium'}}));
  const sections = intel.sections || [];
  sections.forEach(sec => {{
    (sec.items || []).forEach(item => {{
      if (item.highlight) items.push({{title: item.label || item.highlight, severity: item.severity || 'medium'}});
    }});
  }});

  document.getElementById('finding-count').textContent = items.length;
  items.slice(0, 30).forEach(f => {{
    const d = document.createElement('div');
    d.className = 'finding ' + (f.severity || 'medium');
    d.innerHTML = '<div class="title">' + escHtml(f.title) + '</div>';
    el.appendChild(d);
  }});
  if (!items.length) {{
    el.innerHTML = '<div class="nd-empty">No findings yet</div>';
  }}
}}

/* ── Graph ────────────────────────────────────────────────── */
function renderGraph(graphData) {{
  if (!graphData.nodes || !graphData.nodes.length) return;

  const pivotUser = (state.player || {{}}).pivot || '';

  graphNodes = graphData.nodes.map(n => {{
    const isPivot = n.username && n.username.toLowerCase() === pivotUser.toLowerCase();
    const isOwned = n.group === 'operator';
    const isDC = n.group === 'dc';
    const isHV = n.group === 'highvalue';
    const isGroup = n.group === 'group';
    const isComputer = n.group === 'computer';
    const isKerberoastable = n.kerberoastable || n.group === 'kerberoastable';
    const isAsrep = n.asrep_roastable || n.group === 'asrep';
    const isUser = n.group === 'user' || (!isPivot && !isDC && !isOwned && !isHV && !isGroup && !isComputer && !isGmsa);

    /* Size by importance */
    let size = 12;
    if (isPivot) size = 26;
    else if (isDC || isKerberoastable || isAsrep) size = 20;
    else if (isHV) size = 18;
    else if (isOwned) size = 18;
    else if (isGroup) size = 14;
    else if (isComputer) size = 14;

    /* Shape by type */
    let shape = 'dot';
    if (isPivot) shape = 'star';
    else if (isDC) shape = 'diamond';
    else if (isGroup) shape = 'diamond';
    else if (isComputer) shape = 'square';
    else if (isGmsa) shape = 'triangle';
    else if (isKerberoastable || isAsrep) shape = 'hexagon';

    /* Colors - honor backend first, then fallback */
    const backendColor = n.color && (typeof n.color === 'string' ? n.color : n.color.background);
    let color;
    if (isPivot) {{
      color = {{ background: '#f97316', border: '#fb923c', highlight: {{ background: '#fb923c', border: '#fdba74' }} }};
    }} else if (isOwned) {{
      color = {{ background: '#22c55e', border: '#16a34a', highlight: {{ background: '#4ade80', border: '#86efac' }} }};
    }} else if (isDC) {{
      color = {{ background: '#22c55e', border: '#4ade80', highlight: {{ background: '#4ade80', border: '#86efac' }} }};
    }} else if (isHV) {{
      color = {{ background: '#ef4444', border: '#f87171', highlight: {{ background: '#f87171', border: '#fca5a5' }} }};
    }} else if (backendColor === '#ec4899' || isKerberoastable) {{
      color = {{ background: '#ec4899', border: '#f472b6', highlight: {{ background: '#f472b6', border: '#fbcfe8' }} }};
    }} else if (backendColor === '#a855f7' || isAsrep) {{
      color = {{ background: '#a855f7', border: '#c084fc', highlight: {{ background: '#c084fc', border: '#e9d5ff' }} }};
    }} else if (isGroup) {{
      color = {{ background: '#8b5cf6', border: '#a78bfa', highlight: {{ background: '#a78bfa', border: '#c4b5fd' }} }};
    }} else if (isComputer) {{
      color = {{ background: '#6366f1', border: '#818cf8', highlight: {{ background: '#818cf8', border: '#a5b4fc' }} }};
    }} else if (isGmsa) {{
      color = {{ background: '#06b6d4', border: '#22d3ee', highlight: {{ background: '#22d3ee', border: '#67e8f9' }} }};
    }} else {{
      color = {{ background: '#475569', border: '#64748b', highlight: {{ background: '#64748b', border: '#94a3b8' }} }};
    }}

    /* Truncate long labels and strip redundant symbols */
    let label = n.label || n.username || n.id;
    label = label.replace(/^[\\u2605\\u2606\\u2726]\\s*/g, '');  /* Strip star prefix — shape already indicates pivot */
    if (label.length > 22) label = label.substring(0, 20) + '...';

    return {{
      ...n,
      label,
      shape,
      size,
      color,
      borderWidth: isPivot ? 3 : 2,
      shadow: {{ enabled: true, size: isPivot ? 12 : 6, color: 'rgba(0,0,0,0.3)' }},
      font: {{ color: '#e2e8f0', size: isPivot ? 13 : (isDC ? 12 : 10), strokeWidth: 2, strokeColor: '#0a0e1a' }},
    }};
  }});

  graphEdges = graphData.edges.map(e => ({{
    ...e,
    smooth: {{ type: 'dynamic' }},
    font: {{ color: '#64748b', size: 0, strokeWidth: 0 }},
    color: {{ color: '#334155', highlight: '#60a5fa', hover: '#60a5fa', opacity: 0.6 }},
    hoverWidth: 1.5,
  }}));

  const container = document.getElementById('graph-canvas');

  if (network) {{
    network.setData({{
      nodes: new vis.DataSet(graphNodes),
      edges: new vis.DataSet(graphEdges),
    }});
    network.fit();
    return;
  }}

  const graphArea = container.parentElement;
  const w = graphArea.clientWidth;
  const h = graphArea.clientHeight;
  container.style.width = w + 'px';
  container.style.height = h + 'px';

  network = new vis.Network(container, {{
    nodes: new vis.DataSet(graphNodes),
    edges: new vis.DataSet(graphEdges),
  }}, {{
    width: '100%',
    height: '100%',
    autoResize: true,
    physics: {{
      stabilization: {{ iterations: 200, updateInterval: 25 }},
      barnesHut: {{ gravitationalConstant: -5000, springLength: 160, springConstant: 0.03 }},
    }},
    interaction: {{
      hover: true,
      tooltipDelay: 200,
      zoomView: true,
      dragView: true,
      multiselect: false,
    }},
    edges: {{
      arrows: {{ to: {{ enabled: true, scaleFactor: 0.6 }} }},
      smooth: {{ type: 'dynamic' }},
    }},
    nodes: {{
      shape: 'dot',
      size: 12,
      borderWidth: 2,
    }},
  }});

  network.once('stabilizationIterationsDone', () => {{
    network.setOptions({{ physics: false }});
    physicsOn = false;
    document.getElementById('btn-physics').textContent = 'Physics: Off';
    /* Center on pivot if available, otherwise fit all */
    centerOnPivot() || network.fit();
  }});

  /* ResizeObserver */
  const ro = new ResizeObserver(() => {{
    if (!network) return;
    network.redraw();
    network.fit();
  }});
  ro.observe(graphArea);

  /* Click node -> show detail */
  network.on('click', (params) => {{
    if (params.nodes.length) {{
      showNodeDetail(params.nodes[0]);
    }} else {{
      document.getElementById('panel-node-detail').style.display = 'none';
      selectedNodeId = null;
    }}
  }});

  /* Double click -> pivot */
  network.on('doubleClick', (params) => {{
    if (params.nodes.length) {{
      const nodeId = params.nodes[0];
      const node = graphNodes.find(n => n.id === nodeId);
      if (node && node.username) {{
        doPivot(node.username);
        termLog('Pivoting to: ' + node.username, 'cmd');
      }}
    }}
  }});

  /* Hover edge -> show label */
  network.on('hoverEdge', (params) => {{
    const edge = graphEdges.find(e => e.id === params.edge);
    if (edge && edge.label) {{
      network.body.data.edges.update({{ id: params.edge, font: {{ size: 9, color: '#94a3b8', strokeWidth: 0 }} }});
    }}
  }});
  network.on('blurEdge', (params) => {{
    network.body.data.edges.update({{ id: params.edge, font: {{ size: 0 }} }});
  }});
}}

function centerOnPivot() {{
  if (!network) return false;
  const pivotUser = (state.player || {{}}).pivot || '';
  if (!pivotUser) return false;
  const pivotNode = graphNodes.find(n => n.username && n.username.toLowerCase() === pivotUser.toLowerCase());
  if (!pivotNode) return false;
  network.focus(pivotNode.id, {{ scale: 1.2, animation: {{ duration: 500, easingFunction: 'easeInOutQuad' }} }});
  return true;
}}

function graphFit() {{ if (network) network.fit({{ animation: true }}); }}
function graphPhysics() {{
  physicsOn = !physicsOn;
  if (network) network.setOptions({{ physics: physicsOn }});
  document.getElementById('btn-physics').textContent = 'Physics: ' + (physicsOn ? 'On' : 'Off');
}}

/* ── Init ─────────────────────────────────────────────────── */
connectSSE();
refreshState();
termLog('ADMapper dashboard ready', 'done');
</script>
</body>
</html>"""
