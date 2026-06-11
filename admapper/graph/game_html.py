"""AD Ops game — HTML shell, CSS, and client-side JavaScript."""

from __future__ import annotations

import json
from pathlib import Path

from admapper.graph.game_payload import _esc, build_game_payload

def build_game_html(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
    api_mode: bool = False,
) -> str:
    data = build_game_payload(
        ws_path,
        workspace=workspace,
        domain=domain,
        owned_users=owned_users,
        pivot_user=pivot_user,
    )
    payload_json = json.dumps(data)
    api_flag = "true" if api_mode else "false"

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>AD Ops — {_esc(workspace)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;600;700&display=swap" rel="stylesheet"/>
  <script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
  <style>
    :root {{
      --bg: #080b10;
      --panel: #0f1419;
      --border: rgba(255,255,255,0.07);
      --text: #e8edf4;
      --muted: #7a8699;
      --accent: #3dffcf;
      --accent-dim: rgba(61,255,207,0.12);
      --warn: #ffb020;
      --danger: #ff4d6a;
      --owned: #3dffcf;
      --pivot: #ff8c42;
      --success: #22c55e;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'IBM Plex Sans', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      overflow: hidden;
    }}
    /* ── screens ── */
    .screen {{ position: fixed; inset: 0; display: none; flex-direction: column; z-index: 10; }}
    .screen.active {{ display: flex; }}
    #screen-boot {{
      background: #050708;
      flex-direction: column;
    }}
    .boot-wrap {{
      flex: 1;
      display: flex;
      flex-direction: column;
      max-width: 900px;
      width: 100%;
      margin: 0 auto;
      padding: 1.5rem;
    }}
    .boot-banner {{
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.7rem;
      color: var(--muted);
      letter-spacing: 0.12em;
      margin-bottom: 0.75rem;
    }}
    #boot-terminal {{
      flex: 1;
      background: #0a0e12;
      border: 1px solid var(--border);
      padding: 1rem;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.78rem;
      line-height: 1.5;
      color: #9ae6d5;
      overflow-y: auto;
      min-height: 280px;
    }}
    #boot-terminal .line-error {{ color: var(--danger); }}
    #boot-terminal .line-cmd {{ color: var(--accent); }}
    #boot-terminal .line-phase {{ color: var(--warn); }}
    .boot-input-row {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-top: 0.75rem;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.85rem;
    }}
  .boot-input-row span {{ color: var(--accent); }}
    #boot-ip {{
      flex: 1;
      background: transparent;
      border: none;
      border-bottom: 1px solid var(--accent);
      color: var(--text);
      font-family: inherit;
      font-size: inherit;
      padding: 0.35rem 0;
      outline: none;
    }}
    .map-tabs {{
      display: flex; gap: 0.5rem; margin-left: 1rem;
    }}
    .map-tab {{
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.65rem;
      padding: 0.25rem 0.6rem;
      border: 1px solid var(--border);
      background: transparent;
      color: var(--muted);
      cursor: pointer;
    }}
    .map-tab.active {{ border-color: var(--accent); color: var(--accent); }}
    .discovery-log {{
      font-size: 0.72rem;
      color: var(--muted);
      margin-top: 0.5rem;
      max-height: 80px;
      overflow-y: auto;
    }}
    /* ── play HUD ── */
    .top {{
      display: flex; align-items: center; justify-content: space-between;
      padding: 0.75rem 1.25rem;
      border-bottom: 1px solid var(--border);
      background: var(--panel);
      flex-shrink: 0;
    }}
    .brand {{ font-family: 'IBM Plex Mono', monospace; font-weight: 600; font-size: 0.95rem; letter-spacing: 0.12em; color: var(--accent); }}
    .brand span {{ color: var(--muted); font-weight: 400; }}
    .meta {{ font-size: 0.8rem; color: var(--muted); text-align: right; }}
    .meta strong {{ color: var(--text); }}
    .framework-bar {{
      padding: 0.2rem 0.75rem;
      font-size: 0.65rem;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
      font-family: 'IBM Plex Mono', monospace;
    }}
    .phase .ref {{
      font-size: 0.55rem;
      color: var(--muted);
      margin-top: 2px;
      max-width: 7rem;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .study-map details {{ margin-bottom: 0.75rem; }}
    .study-map summary {{ cursor: pointer; font-size: 0.75rem; color: var(--accent); }}
    .study-map table {{ width: 100%; font-size: 0.65rem; border-collapse: collapse; }}
    .study-map td, .study-map th {{ border: 1px solid var(--border); padding: 2px 4px; vertical-align: top; }}
    .phases {{
      display: flex; gap: 0; padding: 0.6rem 1rem;
      background: #0a0e14;
      border-bottom: 1px solid var(--border);
      overflow-x: auto;
      flex-shrink: 0;
    }}
    .phase {{
      flex: 1; min-width: 100px; padding: 0.5rem 0.6rem;
      border-right: 1px solid var(--border);
      position: relative;
      transition: background 0.4s, opacity 0.4s;
    }}
    .phase:last-child {{ border-right: none; }}
    .phase .code {{ font-family: 'IBM Plex Mono', monospace; font-size: 0.62rem; letter-spacing: 0.08em; color: var(--muted); }}
    .phase .title {{ font-size: 0.68rem; margin-top: 0.15rem; font-weight: 600; }}
    .phase.done .code, .phase.done .title {{ color: var(--owned); }}
    .phase.done {{ animation: unlock 0.6s ease; }}
    .phase.active {{ background: var(--accent-dim); box-shadow: inset 0 -2px 0 var(--accent); animation: pulse-phase 2s infinite; }}
    .phase.active .code {{ color: var(--accent); }}
    .phase.locked {{ opacity: 0.4; }}
    .hud-body {{
      display: grid;
      grid-template-columns: 300px 1fr 280px;
      grid-template-rows: 1fr 180px;
      flex: 1;
      min-height: 0;
      height: calc(100vh - 118px);
    }}
    .panel {{
      border-right: 1px solid var(--border);
      overflow-y: auto;
      padding: 1rem;
      background: var(--panel);
      min-height: 0;
    }}
    .panel-right {{ border-right: none; border-left: 1px solid var(--border); }}
    .panel h3 {{
      font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.14em;
      color: var(--muted); margin-bottom: 0.65rem;
    }}
    .graph-wrap {{
      position: relative;
      min-height: 0;
      height: 100%;
      background: var(--bg);
      overflow: hidden;
    }}
    #graph {{
      width: 100%;
      height: 100%;
      min-height: 320px;
    }}
    .scan-overlay {{
      pointer-events: none;
      position: absolute; inset: 0;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(61,255,207,0.03) 2px,
        rgba(61,255,207,0.03) 4px
      );
      animation: scan-sweep 3s linear infinite;
      opacity: 0;
      transition: opacity 0.3s;
    }}
    .scan-overlay.active {{ opacity: 1; }}
    .terminal-wrap {{
      grid-column: 1 / -1;
      border-top: 1px solid var(--border);
      background: #060809;
      display: flex;
      flex-direction: column;
      min-height: 0;
    }}
    .terminal-header {{
      display: flex; align-items: center; justify-content: space-between;
      padding: 0.35rem 0.75rem;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.65rem;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
    }}
    .progress-bar {{
      height: 3px;
      background: var(--border);
      overflow: hidden;
      display: none;
    }}
    .progress-bar.active {{ display: block; }}
    .progress-bar span {{
      display: block; height: 100%; width: 30%;
      background: var(--accent);
      animation: progress-indeterminate 1.2s ease-in-out infinite;
    }}
    #terminal {{
      flex: 1;
      overflow-y: auto;
      padding: 0.5rem 0.75rem;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.72rem;
      line-height: 1.45;
      color: #9ae6d5;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    #terminal .line-cmd {{ color: var(--accent); }}
    #terminal .line-error {{ color: var(--danger); }}
    #terminal .line-phase {{ color: var(--warn); }}
    #terminal .cursor {{
      display: inline-block;
      width: 8px; height: 1em;
      background: var(--accent);
      animation: blink 1s step-end infinite;
      vertical-align: text-bottom;
    }}
    .objective {{
      background: #121820;
      border: 1px solid var(--border);
      border-left: 3px solid var(--accent);
      padding: 0.85rem;
      margin-bottom: 1rem;
    }}
    .objective h2 {{ font-size: 0.85rem; margin-bottom: 0.35rem; }}
    .objective .tech {{ font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem; color: var(--accent); margin-bottom: 0.5rem; }}
    .objective code {{
      display: block; font-family: 'IBM Plex Mono', monospace; font-size: 0.68rem;
      color: var(--muted); word-break: break-all; margin-top: 0.5rem;
      padding: 0.4rem; background: var(--bg); border-radius: 4px;
    }}
    .blocker {{
      border-left-color: var(--danger);
      background: rgba(255,77,106,0.08);
      margin-bottom: 1rem;
      padding: 0.65rem;
      font-size: 0.78rem;
    }}
    .book-reader {{
      position: absolute; inset: 0; overflow-y: auto;
      background: var(--bg); padding: 1.25rem 1.5rem 4rem;
      font-size: 0.88rem; line-height: 1.55;
    }}
    .book-reader[hidden] {{ display: none !important; }}
    .book-header {{ border-bottom: 1px solid var(--border); padding-bottom: 0.75rem; margin-bottom: 1rem; }}
    .book-header h1 {{ font-size: 1.15rem; margin-bottom: 0.25rem; }}
    .book-chapter {{ font-family: 'IBM Plex Mono', monospace; font-size: 0.68rem; color: var(--accent); letter-spacing: 0.1em; }}
    .book-nav {{
      position: sticky; bottom: 0; display: flex; gap: 0.5rem; justify-content: space-between;
      padding: 0.75rem 0; margin-top: 1.5rem; border-top: 1px solid var(--border);
      background: linear-gradient(transparent, var(--bg) 20%);
    }}
    .book-nav button {{
      font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem;
      padding: 0.5rem 0.85rem; border: 1px solid var(--border);
      background: var(--panel); color: var(--text); cursor: pointer;
    }}
    .book-nav button:hover {{ border-color: var(--accent); color: var(--accent); }}
    .book-toc {{ margin-bottom: 1rem; }}
    .book-toc button {{
      display: block; width: 100%; text-align: left; margin: 0.2rem 0;
      padding: 0.35rem 0.5rem; font-size: 0.75rem; border: none;
      background: transparent; color: var(--muted); cursor: pointer;
    }}
    .book-toc button:hover, .book-toc button.active {{ color: var(--accent); }}
    .book-section {{ margin-bottom: 1rem; }}
    .book-section p {{ color: var(--text); margin-bottom: 0.65rem; }}
    .book-section ul {{ margin-left: 1.1rem; color: var(--muted); }}
    .book-section li {{ margin-bottom: 0.35rem; }}
    .book-section table {{ width: 100%; border-collapse: collapse; font-size: 0.78rem; margin: 0.5rem 0; }}
    .book-section th, .book-section td {{ border: 1px solid var(--border); padding: 0.4rem 0.5rem; text-align: left; }}
    .book-section th {{ background: var(--panel); color: var(--accent); }}
    .book-section pre {{
      font-family: 'IBM Plex Mono', monospace; font-size: 0.68rem;
      background: #050708; border: 1px solid var(--border); padding: 0.75rem;
      overflow-x: auto; color: #a8b8cc; margin: 0.5rem 0;
    }}
    .book-diagram {{ margin: 0.75rem 0; overflow-x: auto; }}
    .book-diagram svg {{ max-width: 100%; height: auto; }}
    .book-meta {{ font-size: 0.72rem; color: var(--muted); margin-top: 0.5rem; }}
    .action-btn {{
      display: block;
      width: 100%;
      margin: 0.5rem 0;
      padding: 0.75rem 1rem;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.75rem;
      letter-spacing: 0.08em;
      font-weight: 600;
      border: 1px solid var(--accent);
      background: var(--accent-dim);
      color: var(--accent);
      cursor: pointer;
      transition: all 0.15s;
    }}
    .action-btn:hover:not(:disabled) {{ background: rgba(61,255,207,0.22); }}
    .action-btn:disabled {{ opacity: 0.35; cursor: not-allowed; }}
    .action-btn.running {{ animation: pulse-phase 1s infinite; }}
    .mission-card {{
      background: linear-gradient(135deg, rgba(61,255,207,0.08), rgba(99,102,241,0.06));
      border: 1px solid rgba(61,255,207,0.35);
      padding: 1rem;
      margin-bottom: 1rem;
      animation: pulse-phase 2.5s ease-in-out infinite;
    }}
    .mission-card h2 {{ font-size: 0.7rem; letter-spacing: 0.14em; color: var(--warn); margin-bottom: 0.4rem; }}
    .mission-card .mission-title {{ font-size: 0.95rem; font-weight: 700; margin-bottom: 0.35rem; }}
    .mission-card .mission-reward {{ font-size: 0.72rem; color: var(--owned); margin-top: 0.5rem; }}
    .mission-card .mission-reward::before {{ content: 'RECOMPENSA: '; color: var(--muted); }}
    .mission-btn {{
      border-color: var(--warn);
      color: var(--warn);
      background: rgba(255,176,32,0.12);
      font-size: 0.8rem;
      margin-top: 0.65rem;
    }}
    .mission-btn:hover:not(:disabled) {{ background: rgba(255,176,32,0.25); }}
    .quest-list li {{ cursor: pointer; transition: background 0.15s; }}
    .quest-list li:hover, .quest-list li.selected {{ background: var(--accent-dim); }}
    .quest-list li.selected {{ border-left: 2px solid var(--accent); padding-left: 0.35rem; }}
    .phase-tools {{ margin-top: 1rem; opacity: 0.85; }}
    .phase-tools summary {{ cursor: pointer; font-size: 0.72rem; color: var(--muted); }}
    .cred-form input {{
      width: 100%;
      margin: 0.35rem 0;
      padding: 0.5rem;
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.75rem;
    }}
    .chip {{
      display: inline-block;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.68rem;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      margin: 0.15rem 0.25rem 0.15rem 0;
      border: 1px solid var(--border);
    }}
    .chip.owned {{ border-color: var(--owned); color: var(--owned); }}
    .chip.pivot {{ border-color: var(--pivot); color: var(--pivot); }}
    .chip.pivot-active {{ border-color: var(--pivot); background: rgba(255,140,66,0.15); color: var(--pivot); }}
    .chip.pivot-btn {{ cursor: pointer; }}
    .chip.pivot-btn:hover {{ background: rgba(255,140,66,0.12); }}
    .cred-form label {{ display: block; font-size: 0.68rem; color: var(--muted); margin: 0.5rem 0 0.25rem; }}
    .chip.valid {{ color: var(--owned); }}
    .chip.invalid {{ color: var(--danger); }}
    .list {{ list-style: none; font-size: 0.78rem; }}
    .list li {{ padding: 0.45rem 0; border-bottom: 1px solid var(--border); line-height: 1.35; }}
    .list .sub {{ color: var(--muted); font-size: 0.7rem; font-family: 'IBM Plex Mono', monospace; }}
    .hl {{ font-size: 0.75rem; color: var(--muted); margin-bottom: 0.35rem; }}
    .hl::before {{ content: '▸ '; color: var(--accent); }}
    body.flash-success {{ animation: flash-green 0.5s; }}
    body.flash-error {{ animation: shake 0.4s; }}
    @keyframes glitch {{
      0%, 90%, 100% {{ transform: none; text-shadow: 0 0 40px rgba(61,255,207,0.4); }}
      92% {{ transform: translate(-2px, 1px); text-shadow: 2px 0 var(--danger); }}
      94% {{ transform: translate(2px, -1px); text-shadow: -2px 0 var(--warn); }}
    }}
    @keyframes blink {{ 50% {{ opacity: 0; }} }}
    @keyframes pulse-phase {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.75; }} }}
    @keyframes unlock {{ 0% {{ transform: scale(1); }} 50% {{ transform: scale(1.03); background: rgba(34,197,94,0.15); }} 100% {{ transform: scale(1); }} }}
    @keyframes scan-sweep {{ 0% {{ background-position: 0 0; }} 100% {{ background-position: 0 100px; }} }}
    @keyframes progress-indeterminate {{ 0% {{ transform: translateX(-100%); }} 100% {{ transform: translateX(400%); }} }}
    @keyframes flash-green {{ 0% {{ box-shadow: inset 0 0 0 0 transparent; }} 30% {{ box-shadow: inset 0 0 80px rgba(34,197,94,0.15); }} 100% {{ box-shadow: none; }} }}
    @keyframes shake {{ 0%, 100% {{ transform: translateX(0); }} 25% {{ transform: translateX(-4px); }} 75% {{ transform: translateX(4px); }} }}
    @media (max-width: 1100px) {{
      .hud-body {{ grid-template-columns: 1fr; grid-template-rows: auto minmax(280px, 40vh) auto 160px; }}
      .panel-right {{ border-left: none; border-top: 1px solid var(--border); }}
    }}
  </style>
</head>
<body>
  <!-- BLACKBOX BOOT -->
  <div id="screen-boot" class="screen active">
    <div class="boot-wrap">
      <div class="boot-banner">AD OPS // BLACKBOX ENGAGEMENT — sin intel previa</div>
      <div id="boot-terminal"></div>
      <div class="boot-input-row">
        <span>target&gt;</span>
        <input id="boot-ip" type="text" inputmode="decimal" autocomplete="off" spellcheck="false" placeholder="10.x.x.x"/>
      </div>
    </div>
  </div>

  <!-- PLAY HUD -->
  <div id="screen-play" class="screen">
    <header class="top">
      <div class="brand">AD OPS <span>// {_esc(workspace)}</span></div>
      <div class="map-tabs">
        <button class="map-tab active" id="tab-network" type="button">NETWORK</button>
        <button class="map-tab" id="tab-ad" type="button">AD MAP</button>
        <button class="map-tab" id="tab-manual" type="button">MANUAL</button>
      </div>
      <div class="meta" id="hud-meta"></div>
    </header>
    <div class="framework-bar" id="framework-bar"></div>
    <nav class="phases" id="phases"></nav>
    <div class="hud-body">
      <aside class="panel" id="left"></aside>
      <div class="graph-wrap">
        <div class="scan-overlay" id="scan-overlay"></div>
        <div id="graph"></div>
        <div id="book-reader" class="book-reader" hidden></div>
      </div>
      <aside class="panel panel-right" id="right">
        <div class="discovery-log" id="discovery-log"></div>
      </aside>
      <div class="terminal-wrap">
        <div class="terminal-header">
          <span>TERMINAL // admapper</span>
          <span id="op-status">IDLE</span>
        </div>
        <div class="progress-bar" id="progress-bar"><span></span></div>
        <div id="terminal"><span class="cursor"></span></div>
      </div>
    </div>
  </div>

  <script>
    const API_MODE = {api_flag};
    let GAME = {payload_json};
    let network = null;
    let nodeData = null;
    let edgeData = null;
    let opRunning = false;
    let evtSource = null;
    let screen = 'boot';
    let selectedMissionId = null;
    let viewMode = 'network';
    let bookPageIdx = 0;
    let viewUser = null;

    const $ = (id) => document.getElementById(id);

    function getDisplayLens() {{
      if (viewUser) {{
        const ident = (GAME.selectable_identities || []).find(
          i => i.username.toLowerCase() === viewUser.toLowerCase()
        );
        return (ident && ident.view_lens) ? ident.view_lens : {{}};
      }}
      return GAME.identity_lens || {{}};
    }}

    function getDisplayActions() {{
      let actions = (GAME.actions || []).filter(a => a.enabled !== false);
      if (viewUser) {{
        const globalIds = new Set(['scan', 'cred', 'enum', 'loot', 'acls']);
        actions = actions.filter(a => globalIds.has(a.id));
      }}
      return actions;
    }}

    function getDisplayQuests() {{
      if (viewUser) return [];
      return (GAME.quests || []).filter(q => q.verified);
    }}

    function selectIdentityByName(username) {{
      if (!username) return;
      const identities = GAME.selectable_identities || [];
      const ident = identities.find(i => i.username.toLowerCase() === username.toLowerCase());
      if (!ident) {{
        termLine('Sin perfil operativo para ' + username, 'line-phase');
        return;
      }}
      if (ident.selectable === 'view') {{
        showViewProfile(ident.username);
        return;
      }}
      viewUser = null;
      if (ident.selectable === 'verify') {{
        const el = $('cred-user');
        if (el) el.value = ident.username;
        termLine('Enfoque: ' + ident.username + ' — verifica la pista en el formulario', 'line-phase');
      }}
      setPivot(ident.username);
    }}

    function showViewProfile(username) {{
      viewUser = username;
      selectedMissionId = null;
      const ident = (GAME.selectable_identities || []).find(
        i => i.username.toLowerCase() === username.toLowerCase()
      );
      termLine('Perfil lectura: ' + username + ' — ' + ((ident && ident.detail) || 'enum'), 'line-phase');
      renderAll();
      highlightIdentityGraph();
    }}

    function showScreen(name) {{
      screen = name;
      document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
      $('screen-' + name).classList.add('active');
      if (name === 'play') {{
        requestAnimationFrame(() => initGraph());
        connectEvents();
      }}
    }}

    function activePhase() {{
      return (GAME.phases || []).find(p => p.status === 'active') || null;
    }}

    function termLine(text, cls) {{
      const t = $('terminal');
      const cursor = t.querySelector('.cursor');
      const span = document.createElement('div');
      if (cls) span.className = cls;
      span.textContent = text;
      t.insertBefore(span, cursor);
      t.scrollTop = t.scrollHeight;
    }}

  function typeLine(text, cls, cb) {{
      let i = 0;
      const t = $('terminal');
      const cursor = t.querySelector('.cursor');
      const span = document.createElement('div');
      if (cls) span.className = cls;
      t.insertBefore(span, cursor);
      function tick() {{
        if (i < text.length) {{
          span.textContent += text[i++];
          t.scrollTop = t.scrollHeight;
          setTimeout(tick, 8 + Math.random() * 12);
        }} else if (cb) cb();
      }}
      tick();
    }}

    function setOpState(running) {{
      opRunning = running;
      $('op-status').textContent = running ? 'RUNNING' : 'IDLE';
      $('progress-bar').classList.toggle('active', running);
      $('scan-overlay').classList.toggle('active', running);
      document.querySelectorAll('.action-btn, .mission-btn').forEach(btn => {{
        btn.disabled = running;
        btn.classList.toggle('running', running);
      }});
    }}

    function flash(kind) {{
      document.body.classList.remove('flash-success', 'flash-error');
      void document.body.offsetWidth;
      document.body.classList.add(kind === 'ok' ? 'flash-success' : 'flash-error');
    }}

    async function fetchState() {{
      if (!API_MODE) return;
      try {{
        const r = await fetch('/api/state');
        if (r.ok) GAME = await r.json();
      }} catch (e) {{ /* offline */ }}
    }}

    function renderPhases() {{
      const fb = $('framework-bar');
      if (fb) fb.textContent = GAME.engagement_framework || '';
      const el = $('phases');
      el.innerHTML = (GAME.phases || []).map(p => {{
        const fw = p.framework || {{}};
        const refs = [fw.crtp, (fw.mitre || []).join('/')].filter(Boolean).join(' · ');
        const tip = [p.detail, fw.crtp, fw.crte, fw.crto, (fw.mitre || []).join(', ')].filter(Boolean).join('\\n');
        return `<div class="phase ${{p.status}}" data-id="${{p.id}}" title="${{tip}}">
          <div class="code">${{p.code}}</div>
          <div class="title">${{p.title}}</div>
          <div class="ref">${{refs}}</div>
        </div>`;
      }}).join('');
    }}

    function renderStudyMapPanel() {{
      const rows = GAME.study_map || [];
      if (!rows.length) return '';
      let body = '';
      rows.forEach(r => {{
        body += `<tr><td>P${{String(r.order).padStart(2,'0')}}</td><td>${{r.name}}</td>`
          + `<td>${{r.crtp}}</td><td>${{r.crte !== '—' ? r.crte : ''}}</td>`
          + `<td>${{r.crto !== '—' ? r.crto : ''}}</td>`
          + `<td>${{(r.mitre || []).join(', ')}}</td></tr>`;
      }});
      return `<details class="study-map"><summary>Mapa de estudio (CRTP · CRTE · CRTO · MITRE)</summary>`
        + `<p class="sub">P1–P12 canónico; la barra superior es vista resumida para el juego.</p>`
        + `<table><thead><tr><th>#</th><th>Fase</th><th>CRTP</th><th>CRTE</th><th>CRTO</th><th>MITRE</th></tr></thead>`
        + `<tbody>${{body}}</tbody></table></details>`;
    }}

    function bootLine(text, cls) {{
      const t = $('boot-terminal');
      if (!t) return;
      const div = document.createElement('div');
      if (cls) div.className = cls;
      div.textContent = text;
      t.appendChild(div);
      t.scrollTop = t.scrollHeight;
    }}

    function initBoot() {{
      const t = $('boot-terminal');
      if (!t) return;
      t.innerHTML = '';
      bootLine('AD Ops v1 — modo BLACKBOX');
      bootLine('Sin dominio. Sin credenciales. Sin mapa.');
      bootLine('');
      bootLine('Introduce la IP del objetivo y pulsa Enter.');
      bootLine('Se ejecutará: admapper scan -H <IP>');
      bootLine('');
      const m = GAME.meta || {{}};
      const tip = m.target_ip || m.dc_ip;
      if (tip) {{
        bootLine('IP configurada: ' + tip + ' — Enter para escanear', 'line-phase');
        $('boot-ip').value = tip;
      }}
    }}

    function isValidIp(s) {{
      return /^(?:\\d{{1,3}}\\.){{3}}\\d{{1,3}}$/.test(s.trim());
    }}

    async function submitBootIp() {{
      const ip = ($('boot-ip') || {{}}).value.trim();
      if (!isValidIp(ip)) {{
        bootLine('IP inválida — formato 10.x.x.x', 'line-error');
        return;
      }}
      if (!API_MODE) {{
        bootLine('Inicia el servidor: admapper game -H ' + ip, 'line-error');
        return;
      }}
      bootLine('> scan -H ' + ip, 'line-cmd');
      bootLine('Enumerando Kerberos, LDAP, SMB…');
      try {{
        const r = await fetch('/api/scan', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ ip }}),
        }});
        if (!r.ok) {{
          bootLine('error HTTP ' + r.status, 'line-error');
          return;
        }}
        setOpState(true);
        connectEvents();
        const poll = setInterval(async () => {{
          if (opRunning) return;
          clearInterval(poll);
          await fetchState();
          if ((GAME.topology || {{}}).has_scan) {{
            bootLine('Recon completo — desplegando mapa…', 'line-phase');
            setTimeout(() => enterPlay(), 600);
          }}
        }}, 800);
      }} catch (e) {{
        bootLine('error: ' + e, 'line-error');
      }}
    }}

    function enterPlay() {{
      renderAll();
      showScreen('play');
      termLine('workspace ' + ((GAME.meta || {{}}).workspace || ''));
      termLine('Blackbox — descubre el dominio desde el mapa NETWORK');
    }}

    function renderHudMeta() {{
      const m = GAME.meta || {{}};
      const dom = m.domain_known ? m.domain : '???';
      const dc = m.dc_ip || '—';
      const host = m.dc_host || '';
      $('hud-meta').innerHTML =
        `<div><strong>${{m.workspace}}</strong> · dominio <strong>${{dom}}</strong></div>` +
        `<div>target ${{dc}} ${{host}}</div>`;
    }}

    function renderDiscoveryLog() {{
      const el = $('discovery-log');
      if (!el) return;
      const d = (GAME.topology || {{}}).discoveries || [];
      const pct = (GAME.topology || {{}}).discovery_pct || 0;
      el.innerHTML = '<h3>Descubrimientos (' + pct + '%)</h3>' +
        (d.length ? d.map(x => '<div class="hl">' + x + '</div>').join('') : '<p class="hl">Escanea para revelar topología</p>');
    }}

    function activeGraphData() {{
      if (viewMode === 'ad') return GAME.graph || {{ nodes: [], edges: [] }};
      return GAME.topology || GAME.graph || {{ nodes: [], edges: [] }};
    }}

    function currentMission() {{
      const quests = GAME.quests || [];
      if (selectedMissionId) {{
        const picked = quests.find(q => q.id === selectedMissionId);
        if (picked) return picked;
      }}
      return GAME.mission || null;
    }}

    function renderLeft() {{
      const p = GAME.player || {{}};
      const obj = GAME.objective || {{}};
      const g = GAME.game || {{}};
      const mission = currentMission();
      let html = '';

      html += `<div class="objective"><h2>ESTADO</h2><p><strong>${{g.stage_label || '—'}}</strong></p></div>`;

      const actions = getDisplayActions();
      if (actions.length) {{
        html += '<h3>Acciones disponibles ahora</h3>';
        actions.forEach((a, i) => {{
          const req = a.required ? ' *' : '';
          const cls = i === 0 ? 'action-btn mission-btn' : 'action-btn';
          html += `<button class="${{cls}}" data-aid="${{a.id}}" data-action="${{a.action}}">${{a.button}}${{req}}</button>`;
          if (a.reason) html += `<p class="hl">${{a.reason}}</p>`;
        }});
      }} else {{
        html += '<p class="hl">Nada habilitado — completa el paso anterior</p>';
      }}

      if (g.stage === 'need_creds' && g.game_over) {{
        html += `<p class="hl" style="color:var(--danger)">${{g.game_over_message || 'Sin credenciales no hay juego.'}}</p>`;
      }}

      const lens = getDisplayLens();
      const pivotNow = viewUser
        ? viewUser.toLowerCase()
        : (p.pivot || '').toLowerCase();
      if (lens.username) {{
        const readOnly = lens.read_only || !!viewUser;
        html += `<div class="objective"><h2>PERFIL · ${{lens.username}}${{readOnly ? ' (lectura)' : ''}}</h2>`;
        html += `<p class="sub">${{lens.status_label || ''}}</p>`;
        if ((lens.enum_flags || []).length) {{
          html += `<p class="sub">Flags LDAP: ${{lens.enum_flags.join(', ')}}</p>`;
        }}
        if (lens.inventory) {{
          const inv = lens.inventory;
          if (inv.dn) html += `<p class="sub">${{inv.dn}}</p>`;
          if ((inv.groups || []).length) {{
            html += `<p class="sub">Grupos: ${{inv.groups.slice(0, 5).join(', ')}}</p>`;
          }}
          if (inv.spn_count) html += `<p class="sub">SPNs: ${{inv.spn_count}}</p>`;
        }}
        if (readOnly) {{
          html += '<p class="hl" style="color:var(--warn)">Sin credencial — no es pivot operativo</p>';
        }}
        if (lens.access_matrix) {{
          const r = lens.access_matrix;
          html += `<p class="sub">ldap ${{r[1]}} · smb ${{r[2]}} · krb ${{r[3]}} · winrm ${{r[4]}}</p>`;
        }}
        if ((lens.enabled_missions || []).length) {{
          html += '<p class="sub">Rutas ejecutables:</p><ul class="list">';
          lens.enabled_missions.slice(0, 4).forEach(m => {{
            html += `<li><strong>${{m.technique}}</strong> → ${{m.target}}</li>`;
          }});
          html += '</ul>';
        }} else if ((lens.missions || []).length) {{
          html += '<p class="hl" style="color:var(--warn)">Rutas conocidas pero bloqueadas para este usuario</p>';
        }}
        if (lens.loot_clue) {{
          html += `<p class="sub">Pista: «${{lens.loot_clue.string}}»</p>`;
        }}
        html += '</div>';
      }}

      const identities = GAME.selectable_identities || [];
      if (identities.length) {{
        html += '<h3>Identidades</h3><p class="sub">Clic en el grafo (nodo usuario) o aquí — la UI se perfila a esa identidad.</p><p>';
        identities.forEach(id => {{
          const active = id.username.toLowerCase() === pivotNow ? ' pivot-active' : '';
          const role = id.role || '';
          const mode = id.selectable === 'view' ? ' data-view-only="1"' : '';
          html += `<button type="button" class="chip pivot-btn${{active}}"${{mode}} data-pivot="${{id.username}}" title="${{id.detail || role}}">${{id.username}}</button> `;
        }});
        html += '</p>';
      }}

      const creds = GAME.creds || [];
      if (creds.length) {{
        html += '<p class="sub">Credenciales guardadas en workspace (no se muestran passwords):</p><ul class="list">';
        creds.forEach(c => {{
          const cls = c.status === 'valid' ? 'valid' : '';
          html += `<li><button type="button" class="chip pivot-btn ${{cls}}" data-cred-user="${{c.user}}">${{c.user}}</button> <span class="chip">${{c.status}}</span></li>`;
        }});
        html += '</ul>';
      }}

      html += `<div class="cred-form">
        <label>Autenticar / añadir credencial (cualquier usuario)</label>
        <input id="cred-user" placeholder="usuario (LDAP)" autocomplete="off"/>
        <input id="cred-pass" type="password" placeholder="contraseña" autocomplete="off"/>
        <button type="button" class="action-btn" id="cred-submit" style="margin-top:0.5rem">▶ AUTENTICAR COMO ESTE USUARIO</button>
        <p class="sub">Ejecuta admapper run — añade cred al inventario sin borrar las anteriores.</p>
      </div>
      <div class="cred-form">
        <label>Password spray (P04 CREDS)</label>
        <input id="spray-pass" type="password" placeholder="contraseña para spray" autocomplete="off"/>
        <p class="sub">Usado por la acción ▶ PASSWORD SPRAY cuando el workspace lo permite.</p>
      </div>`;

      if (mission && mission.principal) {{
        html += `<div class="mission-card">
          <h2>// RUTA VERIFICADA</h2>
          <div class="mission-title">${{mission.principal}} → ${{mission.technique}} → ${{mission.target}}</div>
          <p>${{mission.summary || ''}}</p>
          ${{mission.blocked_reason ? `<p class="hl" style="color:var(--warn)">${{mission.blocked_reason}}</p>` : ''}}
        </div>`;
      }}

      (g.targets || []).forEach(t => {{
        html += `<div class="objective"><h2>¿QUIÉN LLEGA A ${{t.target}}?</h2>`;
        html += `<p>${{t.note}}</p>`;
        if ((t.direct_verified || []).length) html += `<p class="hl">✓ ACL: ${{t.direct_verified.join(', ')}}</p>`;
        if ((t.direct_graph_only || []).length) html += `<p class="hl" style="color:var(--warn)">? Grafo: ${{t.direct_graph_only.join('; ')}}</p>`;
        html += '</div>';
      }});

      if (obj.blocker) html += `<div class="objective blocker"><strong>BLOQUEO</strong><br/>${{obj.blocker}}</div>`;
      const hidden = (GAME.graph || {{}}).hidden_nodes || 0;
      if (hidden > 0) html += `<p class="hl">Vista táctica: ${{hidden}} grupos ocultos</p>`;

      html += '<h3>Operador</h3><p>';
      (p.owned || []).forEach(u => html += `<span class="chip owned">${{u}}</span>`);
      if (p.pivot) html += `<span class="chip pivot">pivot: ${{p.pivot}}</span>`;
      html += '</p><h3>Enum destacada</h3>';
      const hl = (GAME.highlights || []).filter(l => l.includes('·'));
      if (hl.length) hl.forEach(l => html += `<div class="hl">${{l.trim().replace(/^·\\s*/, '')}}</div>`);
      else html += '<p class="hl">Ejecuta enum autenticada</p>';
      $('left').innerHTML = html;

      document.querySelectorAll('[data-aid]').forEach(btn => {{
        btn.onclick = () => {{
          const act = (GAME.actions || []).find(a => a.id === btn.dataset.aid);
          if (act) runAction(act);
        }};
      }});
      document.querySelectorAll('[data-pivot]').forEach(btn => {{
        btn.onclick = () => selectIdentityByName(btn.dataset.pivot);
      }});
      document.querySelectorAll('[data-cred-user]').forEach(btn => {{
        btn.onclick = () => {{
          const el = $('cred-user');
          if (el) el.value = btn.dataset.credUser || '';
        }};
      }});
      const credSubmit = $('cred-submit');
      if (credSubmit) {{
        credSubmit.onclick = () => runAction({{ action: 'run', button: 'AUTENTICAR' }});
      }}
    }}

    function parseUsernameFromNode(node) {{
      if (!node) return '';
      if (node.username) return node.username;
      const id = String(node.id || '');
      if (id.startsWith('user:') && id.includes('@')) {{
        return id.split(':')[1].split('@')[0];
      }}
      return String(node.label || '').replace(/^★\\s*/, '').trim();
    }}

    function selectIdentityFromNode(node) {{
      if (!node) return;
      const user = parseUsernameFromNode(node);
      if (!user) return;
      selectIdentityByName(user);
    }}

    function highlightViewGraph(username) {{
      if (!nodeData || !edgeData || !username) return;
      const ul = username.toLowerCase();
      const domain = ((GAME.meta || {{}}).domain || '').toLowerCase();
      const viewId = domain ? ('user:' + ul + '@' + domain) : '';
      nodeData.get().forEach(n => {{
        const nl = (n.username || parseUsernameFromNode(n)).toLowerCase();
        const isView = n.id === viewId || nl === ul;
        const owned = (n.label || '').startsWith('★');
        nodeData.update({{
          id: n.id,
          size: isView ? 28 : 22,
          borderWidth: isView ? 3 : 2,
          color: isView ? '#eab308' : (owned ? '#22c55e' : n.color),
        }});
      }});
      edgeData.get().forEach(e => {{
        edgeData.update({{
          id: e.id,
          width: 2,
          color: {{ color: '#4a5568' }},
        }});
      }});
    }}

    function highlightIdentityGraph() {{
      if (viewUser) return highlightViewGraph(viewUser);
      return highlightPivotGraph();
    }}

    function highlightPivotGraph() {{
      if (!nodeData || !edgeData) return;
      const pivot = ((GAME.player || {{}}).pivot || '').toLowerCase();
      const domain = ((GAME.meta || {{}}).domain || '').toLowerCase();
      const pivotId = pivot && domain ? ('user:' + pivot + '@' + domain) : '';
      nodeData.get().forEach(n => {{
        const ul = (n.username || parseUsernameFromNode(n)).toLowerCase();
        const isPivot = n.id === pivotId || ul === pivot;
        const owned = (n.label || '').startsWith('★');
        nodeData.update({{
          id: n.id,
          size: isPivot ? 30 : 22,
          borderWidth: isPivot ? 4 : 2,
          color: isPivot ? '#f97316' : (owned ? '#22c55e' : n.color),
        }});
      }});
      edgeData.get().forEach(e => {{
        const fromPivot = pivotId && e.from === pivotId;
        edgeData.update({{
          id: e.id,
          width: fromPivot ? 4 : 2,
          color: {{ color: fromPivot ? '#3dffcf' : '#4a5568' }},
        }});
      }});
    }}

    async function setPivot(username) {{
      if (!API_MODE || !username) return;
      viewUser = null;
      termLine('> perfil ' + username, 'line-cmd');
      try {{
        const r = await fetch('/api/pivot', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ username }}),
        }});
        if (r.status === 202) setOpState(true);
        else termLine('error pivot HTTP ' + r.status, 'line-error');
      }} catch (e) {{
        termLine('error: ' + e, 'line-error');
      }}
    }}

    function renderAttackReadinessPanel(intel) {{
      let vectors = (intel || {{}}).attack_readiness || [];
      const lens = getDisplayLens();
      if (viewUser && lens.username) {{
        const vu = viewUser.toLowerCase();
        const flags = lens.enum_flags || [];
        vectors = vectors.filter(v => {{
          if (['recon', 'enum'].includes(v.phase)) return true;
          const aid = (v.attack_id || '').toLowerCase();
          const targets = v.targets || [];
          const hit = t => (t.username || '').toLowerCase() === vu;
          if (flags.includes('asrep') && aid.includes('asrep')) return targets.some(hit);
          if (flags.includes('kerberoast') && aid.includes('kerberoast')) return targets.some(hit);
          return false;
        }});
      }}
      let html = '<h3>Prerrequisitos por ataque</h3>';
      if (!vectors.length) {{
        html += '<p class="hl">Sin vectores — escanea el objetivo</p>';
        return html;
      }}
      const phaseOrder = ['recon', 'creds', 'enum', 'loot', 'escalate'];
      const sorted = [...vectors].sort((a, b) => {{
        const ia = phaseOrder.indexOf(a.phase);
        const ib = phaseOrder.indexOf(b.phase);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
      }});
      sorted.slice(0, 10).forEach(v => {{
        const mark = v.ready ? '✓' : '○';
        const color = v.ready ? 'var(--success)' : 'var(--warn)';
        html += `<p><span style="color:${{color}}">${{mark}}</span> <strong>${{v.title}}</strong> <span class="chip">${{v.phase}}</span></p>`;
        if (v.note) html += `<p class="sub">${{v.note}}</p>`;
        html += '<ul class="list">';
        (v.prerequisites || []).forEach(p => {{
          const pm = p.met ? '✓' : '✗';
          const pc = p.met ? 'var(--muted)' : 'var(--danger)';
          html += `<li><span style="color:${{pc}}">${{pm}}</span> ${{p.label}}<div class="sub">${{p.detail || ''}}</div></li>`;
        }});
        html += '</ul>';
        if ((v.targets || []).length) {{
          html += '<p class="sub">Objetivos:</p><ul class="list">';
          v.targets.slice(0, 5).forEach(t => {{
            const parts = Object.entries(t).map(([k, val]) => `${{k}}=${{val}}`).join(' · ');
            html += `<li class="sub">${{parts}}</li>`;
          }});
          html += '</ul>';
        }}
      }});
      if (vectors.length > 10) html += `<p class="sub">… +${{vectors.length - 10}} vectores</p>`;
      return html;
    }}

    function renderLockoutPanel(intel) {{
      const lp = (intel || {{}}).lockout_policy || {{}};
      const budget = (intel || {{}}).lockout_budget || [];
      const spray = (intel || {{}}).spray_safety || {{}};
      let html = '<h3>Política de bloqueo</h3>';
      if (!lp.lockout_enabled && !lp.lockout_threshold) {{
        html += '<p class="hl">Sin política LDAP aún — enumera el dominio</p>';
        return html;
      }}
      const thresh = lp.lockout_threshold || 0;
      const dur = lp.duration_minutes != null ? lp.duration_minutes + ' min' : '—';
      const win = lp.window_minutes != null ? lp.window_minutes + ' min' : '—';
      html += `<p class="hl">Umbral: <strong>${{thresh}}</strong> · duración: ${{dur}} · ventana: ${{win}}</p>`;
      if (lp.error) html += `<p class="hl" style="color:var(--warn)">${{lp.error}}</p>`;
      if (budget.length) {{
        html += '<p class="sub">Presupuesto por usuario (intentos restantes):</p><ul class="list">';
        budget.slice(0, 12).forEach(b => {{
          const rem = b.attempts_remaining != null ? b.attempts_remaining : '∞';
          const lock = b.locked ? ' [bloqueado]' : '';
          html += `<li><strong>${{b.username}}</strong> badPwd=${{b.bad_pwd_count}} · restantes: ${{rem}}${{lock}}</li>`;
        }});
        if (budget.length > 12) html += `<li class="sub">… +${{budget.length - 12}} más</li>`;
        html += '</ul>';
      }}
      if ((spray.skipped || []).length) {{
        html += '<p class="sub">Spray omitidos:</p><ul class="list">';
        spray.skipped.slice(0, 6).forEach(s => html += `<li class="sub">${{s}}</li>`);
        html += '</ul>';
      }}
      if ((spray.eligible || []).length) {{
        html += `<p class="sub">${{spray.eligible_count}} usuario(s) elegibles para spray</p>`;
      }}
      return html;
    }}

    function renderDomainUsersPanel(intel) {{
      const users = (intel || {{}}).domain_users || [];
      let html = '<h3>Usuarios del dominio</h3>';
      if (!users.length) {{
        html += '<p class="hl">Sin inventario LDAP — ejecuta enum autenticada</p>';
        return html;
      }}
      html += '<ul class="list">';
      users.slice(0, 20).forEach(u => {{
        const en = u.enabled ? 'on' : 'off';
        const bad = u.bad_pwd_count != null ? u.bad_pwd_count : '—';
        const rem = u.attempts_remaining != null ? u.attempts_remaining : '∞';
        const flags = (u.flags || []).map(f => `<span class="chip">${{f}}</span>`).join(' ');
        const spns = u.spn_count ? ` spn:${{u.spn_count}}` : '';
        html += `<li><strong>${{u.username}}</strong> <span class="chip">${{en}}</span>`;
        html += `<div class="sub">badPwd=${{bad}} · restantes: ${{rem}}${{spns}}</div>`;
        if (flags) html += `<div class="sub">${{flags}}</div>`;
        html += '</li>';
      }});
      if (users.length > 20) html += `<li class="sub">… +${{users.length - 20}} usuarios</li>`;
      html += '</ul>';
      return html;
    }}

    function renderPistaAnalysisPanel(intel) {{
      const pa = (intel || {{}}).password_analysis || {{}};
      const rules = pa.rules || [];
      const inferences = pa.inferences || [];
      const transforms = pa.possible_transforms || [];
      let html = '<h3>Análisis de pista</h3>';
      if (!rules.length && !inferences.length) {{
        html += '<p class="hl">Sin pistas parseadas — recolecta loot SMB</p>';
        return html;
      }}
      html += '<p class="sub">Reglas detectadas (sin listas de contraseñas):</p><ul class="list">';
      rules.forEach(r => {{
        html += `<li><strong>${{r.label}}</strong> · ${{r.user}}<div class="sub">${{r.detail}}</div></li>`;
      }});
      html += '</ul>';
      if (inferences.length) {{
        html += '<p class="sub">Inferencias:</p><ul class="list">';
        inferences.forEach(i => {{
          html += `<li><strong>${{i.label}}</strong><div class="sub">${{i.reasoning}}</div></li>`;
        }});
        html += '</ul>';
      }}
      if (transforms.length) {{
        html += '<p class="sub">Transformaciones posibles (tú eliges la contraseña):</p><ul class="list">';
        transforms.forEach(t => {{
          html += `<li><strong>${{t.transform}}</strong> · ${{t.user}}<div class="sub">${{t.description}}</div></li>`;
        }});
        html += '</ul>';
      }}
      return html;
    }}

    function renderOperatorSetupPanel(setup) {{
      setup = setup || {{}};
      let html = '<h3>Tu máquina (prep local)</h3>';
      html += '<p class="hl">El juego no usa sudo. Ejecuta en otra terminal si hace falta.</p>';
      if (setup.clock_ready) {{
        html += '<p class="hl">✓ Reloj / skew Kerberos listo</p>';
      }} else {{
        html += '<p class="hl">⚠ Kerberos puede fallar hasta preparar reloj o libfaketime</p>';
      }}
      const cmds = [];
      if (setup.sync_dc_cmd) cmds.push(['Todo en uno', setup.sync_dc_cmd]);
      if (setup.sync_clock_cmd) cmds.push(['Solo reloj', setup.sync_clock_cmd]);
      if (setup.install_faketime_cmd && !setup.libfaketime_installed) {{
        cmds.push(['libfaketime', setup.install_faketime_cmd]);
      }}
      if (setup.hosts_entry) cmds.push(['/etc/hosts', setup.hosts_entry]);
      if (cmds.length) {{
        html += '<ul class="list">';
        cmds.forEach(([label, cmd]) => {{
          html += `<li><strong>${{label}}</strong><div class="sub mono" title="copiar">${{cmd}}</div></li>`;
        }});
        html += '</ul>';
      }}
      (setup.notes || []).forEach(n => {{ html += `<p class="sub">${{n}}</p>`; }});
      return html;
    }}

    function renderRight() {{
      const intel = GAME.engagement_intel || {{}};
      let html = renderOperatorSetupPanel(GAME.operator_setup);
      html += renderStudyMapPanel();
      html += renderAttackReadinessPanel(intel);
      html += renderLockoutPanel(intel);
      html += renderDomainUsersPanel(intel);
      html += renderPistaAnalysisPanel(intel);

      const lens = getDisplayLens();
      const caps = lens.capabilities || [];
      html += `<h3>Capacidades · ${{lens.username || '—'}}</h3>`;
      if (caps.length) {{
        html += '<ul class="list">';
        caps.slice(0, 10).forEach(c => {{
          const mark = c.verified ? '✓' : (c.graph_only ? '?' : '·');
          const en = c.enabled ? '' : ' — ' + (c.blocked_reason || 'bloqueado');
          html += `<li>${{mark}} <strong>${{c.technique}}</strong> → ${{c.target}}<div class="sub">${{en}}</div></li>`;
        }});
        html += '</ul>';
      }} else {{
        html += '<p class="hl">Sin capacidades indexadas — selecciona un owned con cred o ejecuta acls</p>';
      }}

      const quests = getDisplayQuests();
      html += '<h3>Rutas ACL verificadas</h3><ul class="list quest-list">';
      if (viewUser) {{
        html += '<li><em>Usuario no comprometido — sin rutas ACL</em></li>';
      }} else if (quests.length) {{
        quests.forEach(q => {{
          const sel = q.id === (currentMission() || {{}}).id ? ' selected' : '';
          const st = q.enabled ? '' : ' [bloqueado]';
          html += `<li class="${{sel.trim()}}" data-mid="${{q.id}}">
            <strong>${{q.principal}}</strong> · ${{q.technique}} → ${{q.target}}${{st}}
            <div class="sub">${{q.blocked_reason || q.summary}}</div>
          </li>`;
        }});
      }} else html += '<li><em>Ejecuta acls con un owned</em></li>';
      html += '</ul>';
      html += '<h3>Inventario — credenciales</h3><ul class="list">';
      (GAME.creds || []).forEach(c => {{
        const cls = c.status === 'valid' ? 'valid' : 'invalid';
        html += `<li><strong>${{c.user}}</strong> <span class="chip ${{cls}}">${{c.status}}</span><div class="sub">${{c.source}}</div></li>`;
      }});
      html += '</ul><h3>Pistas (archivos loot)</h3><ul class="list">';
      (GAME.clues || []).forEach(c => {{
        html += `<li><strong>${{c.user}}</strong> <span class="chip">${{c.verify_state}}</span>`;
        html += `<div class="sub">«${{c.string}}»</div>`;
        html += `<div class="sub">${{c.source || '—'}} · conf ${{c.confidence || '?'}}</div></li>`;
      }});
      if (!(GAME.clues || []).length) {{
        html += '<li><em>Sin strings parseados — recolecta loot SMB</em></li>';
      }}
      html += '</ul>';
      if ((GAME.hashes || []).length) {{
        html += '<h3>Hashes</h3><ul class="list">';
        GAME.hashes.forEach(h => html += `<li><strong>${{h.account}}</strong><div class="sub">${{h.nthash}}</div></li>`);
        html += '</ul>';
      }}
      const disc = $('discovery-log');
      if (disc) {{
        $('right').innerHTML = html;
        $('right').prepend(disc);
      }} else {{
        $('right').innerHTML = html;
      }}
      renderDiscoveryLog();
      document.querySelectorAll('.quest-list li').forEach(li => {{
        li.onclick = () => {{
          selectedMissionId = li.dataset.mid;
          renderLeft();
          renderRight();
          highlightMissionEdge(selectedMissionId);
        }};
      }});
    }}

    function highlightMissionEdge(missionId) {{
      if (!edgeData || !missionId) return;
      edgeData.get().forEach(e => {{
        const active = e.mission_id === missionId;
        edgeData.update({{
          id: e.id,
          width: active ? 6 : (e.mission_id ? 4 : 2),
          color: {{ color: active ? '#3dffcf' : (e.mission_id ? '#f59e0b' : '#4a5568') }},
        }});
      }});
    }}

    function renderBookPage(idx) {{
      const book = GAME.pentest_book || {{}};
      const pages = book.pages || [];
      if (!pages.length) return;
      bookPageIdx = Math.max(0, Math.min(idx, pages.length - 1));
      const pg = pages[bookPageIdx];
      const reader = $('book-reader');
      if (!reader) return;
      let html = '<div class="book-header">';
      html += `<div class="book-chapter">${{pg.chapter}} · página ${{pg.page}}</div>`;
      html += `<h1>${{pg.title}}</h1>`;
      if (pg.mitre) html += `<div class="book-meta">MITRE ${{pg.mitre}}</div>`;
      html += '</div>';
      html += '<div class="book-toc">';
      (book.chapters || []).forEach(ch => {{
        const active = ch.name === pg.chapter ? ' active' : '';
        html += `<button type="button" class="${{active}}" data-ch="${{ch.first_page_id}}">${{ch.name}}</button>`;
      }});
      html += '</div>';
      (pg.sections || []).forEach(sec => {{
        html += '<div class="book-section">';
        if (sec.type === 'paragraph') html += `<p>${{sec.text}}</p>`;
        else if (sec.type === 'list') html += '<ul>' + (sec.items || []).map(i => `<li>${{i}}</li>`).join('') + '</ul>';
        else if (sec.type === 'table') {{
          html += '<table><thead><tr>' + (sec.headers || []).map(h => `<th>${{h}}</th>`).join('') + '</tr></thead><tbody>';
          (sec.rows || []).forEach(row => {{ html += '<tr>' + row.map(c => `<td>${{c}}</td>`).join('') + '</tr>'; }});
          html += '</tbody></table>';
        }} else if (sec.type === 'code') html += `<pre>${{sec.text}}</pre>`;
        else if (sec.type === 'diagram') html += `<div class="book-diagram">${{sec.svg}}</div>`;
        html += '</div>';
      }});
      if ((pg.related_vectors || []).length) {{
        html += `<div class="book-meta">Vectores relacionados: ${{pg.related_vectors.join(', ')}}</div>`;
      }}
      html += `<div class="book-nav">
        <button type="button" id="book-prev" ${{bookPageIdx <= 0 ? 'disabled' : ''}}>◀ Anterior</button>
        <span class="book-meta">${{bookPageIdx + 1}} / ${{pages.length}}</span>
        <button type="button" id="book-next" ${{bookPageIdx >= pages.length - 1 ? 'disabled' : ''}}>Siguiente ▶</button>
      </div>`;
      reader.innerHTML = html;
      reader.querySelectorAll('.book-toc button').forEach(btn => {{
        btn.onclick = () => {{
          const id = btn.dataset.ch;
          const i = pages.findIndex(p => p.id === id);
          if (i >= 0) renderBookPage(i);
        }};
      }});
      const prev = $('book-prev');
      const next = $('book-next');
      if (prev) prev.onclick = () => renderBookPage(bookPageIdx - 1);
      if (next) next.onclick = () => renderBookPage(bookPageIdx + 1);
    }}

    function showManualView() {{
      viewMode = 'manual';
      $('graph').style.display = 'none';
      $('scan-overlay').style.display = 'none';
      const reader = $('book-reader');
      if (reader) {{ reader.hidden = false; renderBookPage(bookPageIdx); }}
    }}

    function showGraphView() {{
      $('graph').style.display = '';
      $('scan-overlay').style.display = '';
      const reader = $('book-reader');
      if (reader) reader.hidden = true;
    }}

    function initGraph() {{
      if (viewMode === 'manual') {{
        showManualView();
        return;
      }}
      showGraphView();
      if (typeof vis === 'undefined') {{
        termLine('vis-network no cargado — revisa conexión CDN', 'line-error');
        return;
      }}
      const g = activeGraphData();
      const container = $('graph');
      if (!container) return;

      const nodes = (g.nodes || []).map(n => ({{
        ...n,
        shadow: {{ enabled: true, color: 'rgba(61,255,207,0.3)', size: 12 }},
      }}));
      const edges = g.edges || [];

      const physicsOpts = {{
        enabled: true,
        stabilization: {{ iterations: 120, fit: true }},
        barnesHut: {{
          gravitationalConstant: -4000,
          centralGravity: 0.15,
          springLength: 200,
          springConstant: 0.05,
          avoidOverlap: 0.8,
        }},
      }};

      if (network) {{
        nodeData.clear();
        edgeData.clear();
        nodeData.add(nodes);
        edgeData.add(edges);
        network.setOptions({{ physics: physicsOpts }});
        network.once('stabilizationIterationsDone', () => {{
          network.setOptions({{ physics: {{ enabled: false }} }});
          network.fit({{ animation: {{ duration: 350 }} }});
          highlightIdentityGraph();
          const mid = (currentMission() || {{}}).id;
          if (mid) highlightMissionEdge(mid);
        }});
        network.stabilize(100);
        return;
      }}

      nodeData = new vis.DataSet(nodes);
      edgeData = new vis.DataSet(edges);
      const usePhysics = viewMode === 'ad';
      network = new vis.Network(container, {{ nodes: nodeData, edges: edgeData }}, {{
        physics: usePhysics ? physicsOpts : {{ enabled: false }},
        interaction: {{ hover: true, zoomView: true, dragView: true }},
        nodes: {{ shape: 'dot', size: 22, borderWidth: 2, font: {{ color: '#e8edf4', size: 11 }} }},
        edges: {{
          color: {{ color: '#4a5568', highlight: '#3dffcf' }},
          font: {{ color: '#7a8699', size: 9, strokeWidth: 0 }},
          smooth: {{ type: 'continuous' }},
          width: 2,
        }},
      }});
      network.once('stabilizationIterationsDone', () => {{
        network.setOptions({{ physics: {{ enabled: false }} }});
        pulseDiscovered(nodes);
        highlightIdentityGraph();
        const mid = (currentMission() || {{}}).id;
        if (mid) highlightMissionEdge(mid);
      }});
      network.on('click', (params) => {{
        if (params.nodes.length) {{
          selectIdentityFromNode(nodeData.get(params.nodes[0]));
          return;
        }}
        if (!params.edges.length || !edgeData) return;
        const edge = edgeData.get(params.edges[0]);
        if (!edge || !edge.mission_id) {{
          termLine('Flecha sin misión — prueba un nodo usuario (owned/pivot)', 'line-phase');
          return;
        }}
        selectedMissionId = edge.mission_id;
        renderLeft();
        renderRight();
        highlightMissionEdge(edge.mission_id);
        const q = (GAME.quests || []).find(x => x.id === edge.mission_id);
        if (q) typeLine('Misión: ' + q.title, 'line-phase');
      }});
    }}

    function pulseDiscovered(nodes) {{
      if (!nodeData) return;
      nodes.forEach((n, i) => {{
        setTimeout(() => {{
          try {{
            nodeData.update({{ id: n.id, size: 28 }});
            setTimeout(() => nodeData.update({{ id: n.id, size: 22 }}), 400);
          }} catch (e) {{}}
        }}, i * 120);
      }});
    }}

    function animateExploitEdge() {{
      if (!edgeData) return;
      const edges = edgeData.get();
      edges.forEach(e => {{
        edgeData.update({{ id: e.id, color: {{ color: '#3dffcf' }}, width: 4 }});
      }});
      setTimeout(() => {{
        edges.forEach(e => {{
          edgeData.update({{ id: e.id, color: {{ color: '#4a5568' }}, width: 2 }});
        }});
      }}, 1200);
    }}

    function renderAll() {{
      renderPhases();
      renderHudMeta();
      renderLeft();
      renderRight();
      renderDiscoveryLog();
      if (screen === 'play') initGraph();
    }}

    async function refreshAfterOp(ok) {{
      await fetchState();
      if (!viewUser) {{
        const pivot = ((GAME.player || {{}}).pivot || '').toLowerCase();
        const stillSelectable = (GAME.selectable_identities || []).some(
          i => i.username.toLowerCase() === pivot && i.selectable !== 'view'
        );
        if (pivot && !stillSelectable) viewUser = null;
      }}
      renderAll();
      highlightIdentityGraph();
      if (ok) {{
        flash('ok');
        animateExploitEdge();
      }} else {{
        flash('err');
      }}
    }}

    async function postOp(endpoint, body, label) {{
      setOpState(true);
      typeLine('> ' + label, 'line-cmd');
      try {{
        const r = await fetch(endpoint, {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(body),
        }});
        if (r.status === 409) {{
          termLine('operación ya en curso', 'line-error');
          setOpState(false);
          return false;
        }}
        if (!r.ok) {{
          termLine('error HTTP ' + r.status, 'line-error');
          setOpState(false);
          flash('err');
          return false;
        }}
        return true;
      }} catch (e) {{
        termLine('error de red: ' + e, 'line-error');
        setOpState(false);
        flash('err');
        return false;
      }}
    }}

    async function runAction(act) {{
      if (!act || opRunning) return;
      if (!API_MODE) {{
        termLine('Modo estático — inicia: admapper game -w <workspace>', 'line-error');
        return;
      }}
      const action = act.action || 'exploit';
      let body = {{}};
      if (action === 'run') {{
        body.username = ($('cred-user') || {{}}).value || '';
        body.password = ($('cred-pass') || {{}}).value || '';
        if (!body.username || !body.password) {{
          termLine('Introduce usuario y contraseña', 'line-error');
          return;
        }}
      }}
      if (action === 'brief') body.auto = !!act.auto;
      if (action === 'spray') {{
        body.password = ($('spray-pass') || {{}}).value || '';
        if (!body.password) {{
          termLine('Introduce contraseña para spray (campo spray-pass)', 'line-error');
          return;
        }}
      }}
      const m = act.mission || {{}};
      if (m.requires_pivot) termLine('Principal: ' + m.requires_pivot, 'line-phase');
      await postOp('/api/' + action, body, act.button || action);
    }}

    function connectEvents() {{
      if (!API_MODE || evtSource) return;
      evtSource = new EventSource('/api/events');
      evtSource.onmessage = (ev) => {{
        let data;
        try {{ data = JSON.parse(ev.data); }} catch {{ return; }}
        const kind = data.type || 'log';
        const line = data.line || '';
        if (kind === 'state') {{
          try {{
            const st = JSON.parse(line);
            if (st.refresh) {{
              setOpState(false);
              refreshAfterOp(true);
            }}
          }} catch {{}}
          return;
        }}
        const cls = kind === 'error' ? 'line-error' : (kind === 'cmd' ? 'line-cmd' : (kind === 'phase' ? 'line-phase' : ''));
        if (kind === 'done') {{
          termLine(line, cls);
          setOpState(false);
          refreshAfterOp(true);
        }} else if (kind === 'error' && line.startsWith('[exit')) {{
          termLine(line, 'line-error');
          setOpState(false);
          refreshAfterOp(false);
        }} else {{
          termLine(line, cls);
        }}
      }};
      evtSource.onerror = () => {{ /* reconnect handled by browser */ }};
    }}

    $('boot-ip').addEventListener('keydown', (ev) => {{
      if (ev.key === 'Enter') submitBootIp();
    }});

    function setMapTab(mode) {{
      viewMode = mode;
      ['tab-network', 'tab-ad', 'tab-manual'].forEach(id => $(id).classList.remove('active'));
      $('tab-' + (mode === 'ad' ? 'ad' : mode === 'manual' ? 'manual' : 'network')).classList.add('active');
      if (mode !== 'manual') network = null;
      initGraph();
    }}
    $('tab-network').onclick = () => setMapTab('network');
    $('tab-ad').onclick = () => setMapTab('ad');
    $('tab-manual').onclick = () => setMapTab('manual');

    (function bootOrPlay() {{
      initBoot();
      if ((GAME.meta || {{}}).blackbox === false && (GAME.topology || {{}}).has_scan) {{
        enterPlay();
      }} else {{
        showScreen('boot');
        connectEvents();
      }}
    }})();
  </script>
</body>
</html>"""


def write_game_html(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
) -> Path:
    out = ws_path / "ad_ops.html"
    out.write_text(
        build_game_html(
            ws_path,
            workspace=workspace,
            domain=domain,
            owned_users=owned_users,
            pivot_user=pivot_user,
            api_mode=False,
        ),
        encoding="utf-8",
    )
    return out
