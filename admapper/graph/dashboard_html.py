"""ADMapper Web Dashboard — professional pentest UI (BloodHound-style).

Generates a single-page app with:
- vis-network attack graph (center)
- Real-time scan terminal via SSE (bottom)
- Findings / credentials / attack paths panels (right sidebar)
- Phase progress bar (top)
"""

from __future__ import annotations

import html
import json
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
    owned_s = _esc(", ".join(owned_users or []))

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
  --purple:#8b5cf6;--yellow:#eab308;
  --font:'Segoe UI',system-ui,-apple-system,sans-serif;
  --mono:'JetBrains Mono','Fira Code','Cascadia Code',monospace;
}}
html,body{{height:100%;overflow:hidden;font-family:var(--font);background:var(--bg-dark);color:var(--text)}}
::-webkit-scrollbar{{width:6px}}
::-webkit-scrollbar-track{{background:var(--bg-panel)}}
::-webkit-scrollbar-thumb{{background:var(--border-light);border-radius:3px}}

/* ── Layout ───────────────────────────────────────────────── */
.app{{display:grid;grid-template-rows:auto 1fr auto;height:100vh}}
.header{{
  display:flex;align-items:center;gap:1rem;
  padding:0.5rem 1rem;background:var(--bg-panel);border-bottom:1px solid var(--border);
  z-index:10;
}}
.header .logo{{font-weight:700;font-size:1.1rem;color:var(--accent-glow);letter-spacing:-0.02em}}
.header .meta{{color:var(--text-dim);font-size:0.8rem;display:flex;gap:1rem;flex:1}}
.header .meta span{{display:flex;align-items:center;gap:0.3rem}}
.header .meta strong{{color:var(--text);font-weight:500}}
.header .status{{
  display:flex;align-items:center;gap:0.4rem;font-size:0.75rem;
  padding:0.25rem 0.6rem;border-radius:999px;
}}
.status-idle{{background:#14532d;color:#86efac}}
.status-running{{background:#713f12;color:#fde68a}}

.main{{display:grid;grid-template-columns:1fr 320px;overflow:hidden}}
.graph-area{{position:relative;background:var(--bg-dark)}}
#graph-canvas{{width:100%;height:100%}}
.graph-controls{{
  position:absolute;top:0.75rem;left:0.75rem;display:flex;gap:0.4rem;z-index:5;
}}
.graph-controls button{{
  background:var(--bg-card);border:1px solid var(--border-light);color:var(--text);
  padding:0.35rem 0.6rem;border-radius:4px;font-size:0.75rem;cursor:pointer;
}}
.graph-controls button:hover{{background:var(--bg-hover)}}

/* Legend overlay */
.legend{{
  position:absolute;bottom:0.75rem;left:0.75rem;
  background:var(--bg-card);border:1px solid var(--border-light);
  border-radius:6px;padding:0.5rem 0.75rem;font-size:0.7rem;z-index:5;
  display:flex;gap:0.75rem;align-items:center;
}}
.legend-item{{display:flex;align-items:center;gap:0.3rem}}
.legend-dot{{width:8px;height:8px;border-radius:2px;flex-shrink:0}}

/* ── Right Sidebar ────────────────────────────────────────── */
.sidebar{{
  background:var(--bg-panel);border-left:1px solid var(--border);
  overflow-y:auto;display:flex;flex-direction:column;
}}
.panel{{border-bottom:1px solid var(--border);padding:0.75rem}}
.panel-header{{
  font-size:0.7rem;text-transform:uppercase;letter-spacing:0.06em;
  color:var(--text-muted);font-weight:600;margin-bottom:0.5rem;
  display:flex;justify-content:space-between;align-items:center;
}}
.panel-count{{
  background:var(--bg-card);padding:0.1rem 0.4rem;border-radius:999px;
  font-size:0.65rem;color:var(--text-dim);
}}

/* Phase bar */
.phases{{display:flex;gap:2px;margin-bottom:0.25rem}}
.phase{{
  flex:1;height:4px;border-radius:2px;background:var(--border-light);
  position:relative;
}}
.phase.done{{background:var(--green)}}
.phase.partial{{background:var(--yellow)}}
.phase-labels{{display:flex;justify-content:space-between;font-size:0.6rem;color:var(--text-muted)}}

/* Action buttons */
.actions{{display:flex;flex-wrap:wrap;gap:0.35rem;margin-top:0.5rem}}
.btn{{
  padding:0.3rem 0.6rem;border-radius:4px;font-size:0.72rem;font-weight:500;
  cursor:pointer;border:1px solid var(--border-light);background:var(--bg-card);
  color:var(--text);transition:all 0.15s;
}}
.btn:hover:not(:disabled){{background:var(--bg-hover);border-color:var(--accent)}}
.btn:disabled{{opacity:0.4;cursor:not-allowed}}
.btn-primary{{background:var(--accent);border-color:var(--accent);color:#fff}}
.btn-primary:hover:not(:disabled){{background:#2563eb}}

/* Findings list */
.finding{{
  padding:0.4rem 0.5rem;margin-bottom:0.35rem;border-radius:4px;
  background:var(--bg-card);border-left:3px solid var(--text-muted);
  font-size:0.75rem;
}}
.finding.critical{{border-color:var(--red)}}
.finding.high{{border-color:var(--orange)}}
.finding.medium{{border-color:var(--yellow)}}
.finding .title{{font-weight:500;margin-bottom:0.15rem}}
.finding .detail{{color:var(--text-dim);font-size:0.7rem}}

/* Credential rows */
.cred-row{{
  display:flex;justify-content:space-between;align-items:center;
  padding:0.3rem 0.5rem;margin-bottom:0.2rem;border-radius:3px;
  background:var(--bg-card);font-size:0.75rem;
}}
.cred-row .user{{font-weight:500}}
.cred-row .badge{{
  padding:0.1rem 0.35rem;border-radius:3px;font-size:0.65rem;font-weight:600;
}}
.badge-valid{{background:#14532d;color:#86efac}}
.badge-hash{{background:#312e81;color:#a5b4fc}}
.badge-owned{{background:#7c2d12;color:#fdba74}}

/* Identity card */
.identity-card{{
  background:var(--bg-card);border-radius:6px;padding:0.6rem;
  margin-bottom:0.4rem;border:1px solid var(--border-light);
}}
.identity-card .name{{font-weight:600;font-size:0.85rem}}
.identity-card .role{{font-size:0.7rem;color:var(--text-dim)}}

/* ── Bottom Terminal ──────────────────────────────────────── */
.terminal-bar{{
  background:var(--bg-panel);border-top:1px solid var(--border);
  display:flex;flex-direction:column;height:180px;min-height:80px;
  resize:vertical;overflow:hidden;
}}
.terminal-header{{
  display:flex;justify-content:space-between;align-items:center;
  padding:0.35rem 0.75rem;font-size:0.7rem;color:var(--text-muted);
  border-bottom:1px solid var(--border);flex-shrink:0;
}}
.terminal-header .dot{{width:6px;height:6px;border-radius:50%;margin-right:0.3rem}}
.terminal-output{{
  flex:1;overflow-y:auto;padding:0.5rem 0.75rem;
  font-family:var(--mono);font-size:0.72rem;line-height:1.6;
}}
.term-line{{white-space:pre-wrap;word-break:break-all}}
.term-cmd{{color:var(--accent-glow);font-weight:600}}
.term-done{{color:var(--green)}}
.term-error{{color:var(--red)}}
.term-phase{{color:var(--cyan);font-weight:500}}
.term-log{{color:var(--text-dim)}}
.term-time{{color:var(--text-muted);font-size:0.6rem;margin-right:0.4rem}}

/* ── Input bar ────────────────────────────────────────────── */
.input-bar{{
  display:flex;gap:0.5rem;padding:0.4rem 0.75rem;
  border-top:1px solid var(--border);background:var(--bg-card);flex-shrink:0;
}}
.input-bar input{{
  flex:1;background:var(--bg-dark);border:1px solid var(--border-light);
  color:var(--text);padding:0.3rem 0.5rem;border-radius:4px;
  font-family:var(--mono);font-size:0.75rem;outline:none;
}}
.input-bar input:focus{{border-color:var(--accent)}}
.input-bar input::placeholder{{color:var(--text-muted)}}

/* ── Node tooltip ─────────────────────────────────────────── */
.vis-tooltip{{
  background:var(--bg-card)!important;color:var(--text)!important;
  border:1px solid var(--border-light)!important;border-radius:6px!important;
  padding:0.5rem 0.75rem!important;font-size:0.75rem!important;
  font-family:var(--mono)!important;max-width:350px!important;
  box-shadow:0 4px 12px rgba(0,0,0,0.4)!important;
}}

/* ── Responsive ───────────────────────────────────────────── */
@media(max-width:900px){{
  .main{{grid-template-columns:1fr}}
  .sidebar{{max-height:40vh;border-left:none;border-top:1px solid var(--border)}}
}}
</style>
</head>
<body>
<div class="app">

  <!-- ── Header ─────────────────────────────────────────── -->
  <div class="header">
    <span class="logo">ADMapper</span>
    <div class="meta">
      <span>Workspace: <strong id="h-workspace">{workspace_s}</strong></span>
      <span>Domain: <strong id="h-domain">{domain_s or '...'}</strong></span>
      <span>DC: <strong id="h-dc">...</strong></span>
      <span>Pivot: <strong id="h-pivot">{pivot_s or 'none'}</strong></span>
    </div>
    <div class="status status-idle" id="h-status">
      <span class="dot" style="background:var(--green)"></span> Ready
    </div>
  </div>

  <!-- ── Main: Graph + Sidebar ──────────────────────────── -->
  <div class="main">
    <div class="graph-area">
      <div class="graph-controls">
        <button onclick="graphFit()" title="Fit graph">Fit</button>
        <button onclick="graphPhysics()" id="btn-physics" title="Toggle physics">Physics</button>
        <button onclick="refreshState()" title="Refresh data">Refresh</button>
      </div>
      <div id="graph-canvas"></div>
      <div class="legend">
        <div class="legend-item"><span class="legend-dot" style="background:var(--green)"></span>Owned</div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--orange)"></span>Pivot</div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--red)"></span>High value</div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--cyan)"></span>gMSA</div>
        <div class="legend-item"><span class="legend-dot" style="background:var(--purple)"></span>Group</div>
        <div class="legend-item"><span class="legend-dot" style="background:#6366f1"></span>Computer</div>
      </div>
    </div>

    <div class="sidebar">
      <!-- Phases -->
      <div class="panel">
        <div class="panel-header">Attack Chain <span class="panel-count" id="phase-count">0/12</span></div>
        <div class="phases" id="phase-bar"></div>
        <div class="phase-labels"><span>P01</span><span>P06</span><span>P12</span></div>
      </div>

      <!-- Actions -->
      <div class="panel" id="panel-actions">
        <div class="panel-header">Actions</div>
        <div class="actions" id="action-buttons"></div>
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

      <!-- Identities -->
      <div class="panel">
        <div class="panel-header">Identities <span class="panel-count" id="id-count">0</span></div>
        <div id="identity-list"></div>
      </div>
    </div>
  </div>

  <!-- ── Terminal ───────────────────────────────────────── -->
  <div class="terminal-bar">
    <div class="terminal-header">
      <span><span class="dot" style="background:var(--green)"></span> Terminal</span>
      <span id="term-status">waiting for events...</span>
    </div>
    <div class="terminal-output" id="terminal"></div>
    <div class="input-bar">
      <input id="input-user" placeholder="username" style="max-width:140px"/>
      <input id="input-pass" placeholder="password" type="password" style="max-width:160px"/>
      <button class="btn btn-primary" onclick="doAuth()">Authenticate</button>
      <input id="input-ip" placeholder="target IP" style="max-width:130px"/>
      <button class="btn" onclick="doScan()">Scan</button>
    </div>
  </div>

</div>

<script>
/* ── State ────────────────────────────────────────────────── */
let state = {{}};
let network = null;
let physicsOn = true;

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
}}

function escHtml(s) {{
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
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
    el.className = 'status status-running';
    el.innerHTML = '<span class="dot" style="background:var(--yellow)"></span> Running';
  }} else if (kind === 'done' || kind === 'error') {{
    el.className = 'status status-idle';
    el.innerHTML = '<span class="dot" style="background:var(--green)"></span> Ready';
    setTimeout(refreshState, 500);
  }}
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
  const pw = prompt('Password to spray:');
  if (pw) apiPost('/api/spray', {{password: pw}});
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
  document.getElementById('h-workspace').textContent = meta.workspace || '';
  document.getElementById('h-domain').textContent = meta.domain || '...';
  document.getElementById('h-dc').textContent = meta.dc_ip ? (meta.dc_host || meta.dc_ip) : '...';
  document.getElementById('h-pivot').textContent = (s.player||{{}}).pivot || 'none';

  renderPhases(s.phases || []);
  renderActions(s);
  renderCredentials(s.creds || [], s.pth_sessions || []);
  renderHashes(s.pth_sessions || []);
  renderPaths(s.quests || [], s.objective || {{}});
  renderFindings(s.highlights || [], s.engagement_intel || {{}});
  renderIdentities(s.selectable_identities || []);
  renderGraph(s.graph || {{}});
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

/* ── Actions ──────────────────────────────────────────────── */
function renderActions(s) {{
  const container = document.getElementById('action-buttons');
  container.innerHTML = '';
  const progress = s.progress || {{}};
  const btns = [
    {{ label: 'Enum Users', fn: 'doEnum()', show: true }},
    {{ label: 'AS-REP Roast', fn: 'doAsrep()', show: true }},
    {{ label: 'Kerberoast', fn: 'doKerb()', show: true }},
    {{ label: 'Spray', fn: 'doSpray()', show: true }},
    {{ label: 'Exploit', fn: 'doExploit()', show: progress.scan }},
    {{ label: 'ACLs', fn: 'doAcls()', show: progress.scan }},
    {{ label: 'Brief', fn: 'doBrief()', show: progress.exploit }},
  ];
  btns.forEach(b => {{
    if (!b.show) return;
    const el = document.createElement('button');
    el.className = 'btn';
    el.textContent = b.label;
    el.setAttribute('onclick', b.fn);
    container.appendChild(el);
  }});
}}

/* ── Credentials ──────────────────────────────────────────── */
function renderCredentials(creds, pth) {{
  const el = document.getElementById('cred-list');
  el.innerHTML = '';
  const total = creds.length + pth.length;
  document.getElementById('cred-count').textContent = total;
  if (!total) {{
    el.innerHTML = '<div style="font-size:0.72rem;color:var(--text-muted)">No credentials yet</div>';
    return;
  }}
  creds.forEach(c => {{
    const row = document.createElement('div');
    row.className = 'cred-row';
    row.innerHTML = '<span class="user">' + escHtml(c.user) + '</span>' +
      '<span class="badge badge-valid">' + escHtml(c.status) + '</span>';
    row.style.cursor = 'pointer';
    row.onclick = () => doPivot(c.user);
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
    row.title = h.winrm_cmd || h.nthash;
    row.style.cursor = 'pointer';
    row.onclick = () => {{
      if (h.winrm_cmd) {{
        navigator.clipboard.writeText(h.winrm_cmd);
        termLog('Copied: ' + h.winrm_cmd, 'done');
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
    ob.innerHTML = '<div class="title">Next: ' + escHtml(objective.headline) + '</div>' +
      (objective.command ? '<div class="detail"><code>' + escHtml(objective.command) + '</code></div>' : '');
    el.appendChild(ob);
  }}
  ready.forEach(q => {{
    const f = document.createElement('div');
    f.className = 'finding ' + (q.severity || 'medium');
    f.innerHTML = '<div class="title">' + escHtml(q.title) + '</div>' +
      '<div class="detail">' + escHtml(q.technique || '') + ' &rarr; ' + escHtml(q.target || '') + '</div>';
    if (q.ready) {{
      f.style.cursor = 'pointer';
      f.onclick = () => apiPost('/api/exploit');
    }}
    el.appendChild(f);
  }});
  if (!ready.length && !objective.headline) {{
    el.innerHTML = '<div style="font-size:0.72rem;color:var(--text-muted)">Run ACLs to discover paths</div>';
  }}
}}

/* ── Findings ─────────────────────────────────────────────── */
function renderFindings(highlights, intel) {{
  const el = document.getElementById('finding-list');
  el.innerHTML = '';
  const items = [];
  highlights.forEach(h => items.push({{title: h, severity: 'medium'}}));
  const sections = intel.sections || [];
  sections.forEach(sec => {{
    (sec.items || []).forEach(item => {{
      if (item.highlight) items.push({{title: item.label || item.highlight, severity: item.severity || 'medium'}});
    }});
  }});
  document.getElementById('finding-count').textContent = items.length;
  items.slice(0, 20).forEach(f => {{
    const d = document.createElement('div');
    d.className = 'finding ' + (f.severity || 'medium');
    d.innerHTML = '<div class="title">' + escHtml(f.title) + '</div>';
    el.appendChild(d);
  }});
  if (!items.length) {{
    el.innerHTML = '<div style="font-size:0.72rem;color:var(--text-muted)">No findings yet</div>';
  }}
}}

/* ── Identities ───────────────────────────────────────────── */
function renderIdentities(ids) {{
  const el = document.getElementById('identity-list');
  el.innerHTML = '';
  document.getElementById('id-count').textContent = ids.length;
  ids.forEach(id => {{
    const card = document.createElement('div');
    card.className = 'identity-card';
    const role = id.selectable === 'pivot' ? 'Pivot' : (id.selectable === 'view' ? 'View' : '');
    card.innerHTML = '<div class="name">' + escHtml(id.username) + '</div>' +
      '<div class="role">' + escHtml(id.role || '') + (role ? ' &middot; ' + role : '') + '</div>';
    if (id.selectable === 'pivot') {{
      card.style.cursor = 'pointer';
      card.style.borderColor = 'var(--accent)';
      card.onclick = () => doPivot(id.username);
    }}
    el.appendChild(card);
  }});
}}

/* ── Graph ────────────────────────────────────────────────── */
function renderGraph(graphData) {{
  if (!graphData.nodes || !graphData.nodes.length) return;

  const nodes = graphData.nodes.map(n => ({{
    ...n,
    shape: n.shape || 'dot',
    size: n.group === 'dc' ? 24 : (n.group === 'operator' ? 20 : 16),
    borderWidth: 2,
    shadow: {{ enabled: true, size: 8, color: 'rgba(0,0,0,0.3)' }},
    font: n.font || {{ color: '#e2e8f0', size: 11 }},
  }}));

  const edges = graphData.edges.map(e => ({{
    ...e,
    smooth: {{ type: 'dynamic' }},
    font: {{ color: '#94a3b8', size: 9, strokeWidth: 0 }},
  }}));

  const container = document.getElementById('graph-canvas');

  if (network) {{
    // Update existing network
    network.setData({{
      nodes: new vis.DataSet(nodes),
      edges: new vis.DataSet(edges),
    }});
    return;
  }}

  network = new vis.Network(container, {{
    nodes: new vis.DataSet(nodes),
    edges: new vis.DataSet(edges),
  }}, {{
    physics: {{
      stabilization: {{ iterations: 150 }},
      barnesHut: {{ gravitationalConstant: -6000, springLength: 180 }},
    }},
    interaction: {{
      hover: true,
      tooltipDelay: 100,
      zoomView: true,
      dragView: true,
    }},
    edges: {{
      arrows: {{ to: {{ enabled: true, scaleFactor: 0.7 }} }},
      smooth: {{ type: 'dynamic' }},
    }},
    nodes: {{
      shape: 'dot',
      size: 16,
      borderWidth: 2,
      shadow: true,
    }},
  }});

  network.once('stabilizationIterationsDone', () => {{
    network.setOptions({{ physics: false }});
    physicsOn = false;
    document.getElementById('btn-physics').textContent = 'Physics: Off';
  }});

  // Click node to pivot
  network.on('click', (params) => {{
    if (params.nodes.length) {{
      const nodeId = params.nodes[0];
      const node = nodes.find(n => n.id === nodeId);
      if (node && node.username) {{
        termLog('Selected: ' + node.username, 'log');
      }}
    }}
  }});

  // Double click to pivot
  network.on('doubleClick', (params) => {{
    if (params.nodes.length) {{
      const nodeId = params.nodes[0];
      const node = nodes.find(n => n.id === nodeId);
      if (node && node.username) doPivot(node.username);
    }}
  }});
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
