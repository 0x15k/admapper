"""Cheatsheet Workspace view — dual-mode dashboard presentation assets."""

from __future__ import annotations

from admapper.guides.cheatsheet_catalog import cheatsheet_catalog_json

CHEATSHEET_VIEW_TOGGLE = """
<div class="view-toggle" id="view-toggle">
  <button type="button" class="view-btn active" data-view="ops" onclick="setDashboardView('ops')">
    <i class="fa-solid fa-project-diagram"></i> Ops
  </button>
  <button type="button" class="view-btn" data-view="cheatsheet" onclick="setDashboardView('cheatsheet')">
    <i class="fa-solid fa-book"></i> Cheatsheet
  </button>
</div>
"""

CHEATSHEET_CSS = """
.view-toggle{display:flex;gap:0.25rem;margin-right:0.5rem}
.view-btn{background:var(--bg-card);border:1px solid var(--border);color:var(--text-dim);
  padding:0.28rem 0.55rem;border-radius:4px;font-size:0.68rem;font-weight:600;cursor:pointer}
.view-btn:hover{background:var(--bg-hover);color:var(--text)}
.view-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
#view-cheatsheet{display:none;flex:1;min-height:0;overflow:hidden;grid-template-columns:240px 1fr;background:var(--bg-dark)}
#view-cheatsheet.active{display:grid}
#view-ops{display:flex;flex:1;min-height:0;overflow:hidden}
#view-ops.hidden{display:none}
.cheatsheet-view{flex:1;min-height:0;overflow:hidden}
.cs-sidebar{background:var(--bg-panel);border-right:1px solid var(--border);overflow-y:auto;padding:0.5rem}
.cs-sidebar-label{font-size:0.62rem;text-transform:uppercase;letter-spacing:0.1em;color:var(--text-muted);
  font-weight:700;padding:0.35rem 0.5rem}
.cs-vars{display:grid;gap:0.35rem;padding:0.35rem 0.5rem 0.65rem;border-bottom:1px solid var(--border)}
.cs-vars input{background:var(--bg-card);border:1px solid var(--border);color:var(--text);
  padding:0.28rem 0.4rem;border-radius:4px;font-size:0.68rem;width:100%}
.cs-phase-btn{display:block;width:100%;text-align:left;background:transparent;border:none;color:var(--text-dim);
  padding:0.35rem 0.55rem;border-radius:4px;font-size:0.72rem;cursor:pointer}
.cs-phase-btn:hover,.cs-phase-btn.active{background:var(--bg-hover);color:var(--text)}
.cs-main{display:flex;flex-direction:column;min-height:0;overflow:hidden}
.cs-header{padding:0.65rem 0.85rem;border-bottom:1px solid var(--border);background:var(--bg-panel)}
.cs-header h2{font-size:0.95rem;margin:0 0 0.2rem}
.cs-header p{font-size:0.68rem;color:var(--text-dim);margin:0}
.cs-subtabs{display:flex;gap:0.25rem;flex-wrap:wrap;padding:0.45rem 0.85rem;border-bottom:1px solid var(--border)}
.cs-subtab{background:var(--bg-card);border:1px solid var(--border);color:var(--text-dim);
  padding:0.22rem 0.5rem;border-radius:4px;font-size:0.65rem;cursor:pointer}
.cs-subtab.active{background:var(--accent);border-color:var(--accent);color:#fff}
.cs-toolbar{display:flex;gap:0.35rem;align-items:center;padding:0.45rem 0.85rem;flex-wrap:wrap}
.cs-toolbar input{flex:1;min-width:140px;background:var(--bg-card);border:1px solid var(--border);
  color:var(--text);padding:0.32rem 0.45rem;border-radius:4px;font-size:0.68rem}
.cs-filter{background:var(--bg-card);border:1px solid var(--border);color:var(--text-dim);
  padding:0.28rem 0.45rem;border-radius:4px;font-size:0.64rem;cursor:pointer}
.cs-filter.on{border-color:var(--green);color:var(--green)}
.cs-content{flex:1;overflow-y:auto;padding:0.65rem 0.85rem}
.cs-card{background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:0.55rem 0.65rem;margin-bottom:0.45rem}
.cs-card h3{font-size:0.78rem;margin:0 0 0.25rem}
.cs-card .meta{font-size:0.62rem;color:var(--text-dim);margin-bottom:0.35rem}
.cs-card pre{background:#0d1117;border:1px solid var(--border);border-radius:4px;padding:0.4rem;
  font-family:var(--mono);font-size:0.64rem;white-space:pre-wrap;word-break:break-word;margin:0 0 0.35rem}
.cs-card-actions{display:flex;gap:0.3rem;flex-wrap:wrap}
.cs-card-actions button{font-size:0.62rem;padding:0.22rem 0.45rem;border-radius:4px;cursor:pointer;
  border:1px solid var(--border);background:var(--bg-hover);color:var(--text)}
.cs-card-actions button.run{border-color:var(--accent);color:var(--accent-glow)}
.cs-card-actions button.run:disabled{opacity:0.45;cursor:not-allowed;border-color:var(--border);color:var(--text-muted)}
.cs-attack-panel{border-top:1px solid var(--border);max-height:22%;overflow-y:auto;padding:0.5rem 0.85rem;background:var(--bg-panel)}
.cs-notes-panel{border-top:1px solid var(--border);max-height:18%;overflow-y:auto;padding:0.5rem 0.85rem;background:var(--bg-panel)}
.cs-notes-panel textarea{width:100%;min-height:48px;background:var(--bg-card);border:1px solid var(--border);
  color:var(--text);font-size:0.64rem;padding:0.35rem;border-radius:4px;resize:vertical}
.cs-card.highlight{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
"""

CHEATSHEET_HTML = """
<div id="view-cheatsheet" class="cheatsheet-view">
  <aside class="cs-sidebar">
    <div class="cs-sidebar-label">Global Variables</div>
    <div class="cs-vars" id="cs-vars-panel"></div>
    <div class="cs-sidebar-label">Pentest Phases</div>
    <nav id="cs-phase-nav"></nav>
  </aside>
  <div class="cs-main">
    <div class="cs-header">
      <h2 id="cs-phase-title">Cheatsheet</h2>
      <p id="cs-phase-desc">Workspace-aware command browser</p>
    </div>
    <div class="cs-subtabs" id="cs-subtabs"></div>
    <div class="cs-toolbar">
      <input type="text" id="cs-search" placeholder="Search commands, tools, tags…" />
      <button type="button" class="cs-filter" id="cs-filter-stealth" onclick="CheatsheetView.toggleFilter('stealthy')">Low Noise</button>
      <button type="button" class="cs-filter" id="cs-filter-highval" onclick="CheatsheetView.toggleFilter('high-value')">High Value</button>
    </div>
    <div class="cs-content" id="cs-content"></div>
    <div class="cs-attack-panel" id="cs-attack-panel">
      <div class="cs-sidebar-label">Attack Paths (workspace)</div>
      <div id="cs-paths-list"><div class="nd-empty">Select a path in Ops view or wait for paths.json</div></div>
    </div>
    <div class="cs-notes-panel" id="cs-notes-panel">
      <div class="cs-sidebar-label">Findings Notes</div>
      <textarea id="cs-notes-input" placeholder="Operator notes for this workspace…"></textarea>
      <div style="margin-top:0.35rem;display:flex;gap:0.3rem">
        <button type="button" class="cs-filter on" onclick="CheatsheetView.saveNotes()">Save notes</button>
        <button type="button" class="cs-filter" onclick="CheatsheetView.openParser()">Output parser</button>
      </div>
    </div>
  </div>
</div>
"""

CHEATSHEET_JS = r"""
const CheatsheetView = (function () {
  let catalog = { phases: [] };
  let activePhase = null;
  let activeSub = null;
  let search = '';
  let tagFilter = null;
  let paths = [];
  let nextActionCmd = '';

  function latestVars() {
    if (typeof WorkspaceVars !== 'undefined') return WorkspaceVars.get();
    return (typeof state !== 'undefined' && state.cheatsheet_vars)
      ? Object.assign({}, state.cheatsheet_vars) : {};
  }

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = String(s == null ? '' : s);
    return d.innerHTML;
  }

  function subst(cmd, hop) {
    if (typeof CommandCheatsheet !== 'undefined' && CommandCheatsheet.substitute) {
      const extra = typeof WorkspaceVars !== 'undefined'
        ? WorkspaceVars.toSubstExtra() : {};
      if (hop) Object.assign(extra, hop);
      return CommandCheatsheet.substitute(cmd, extra);
    }
    return cmd;
  }

  function renderVars() {
    const panel = document.getElementById('cs-vars-panel');
    if (!panel) return;
    const v = latestVars();
    const fields = ['DOMAIN','DC_IP','USERNAME','PASSWORD','NTLM_HASH','ATTACKER_IP','CA_NAME','TEMPLATE','workspace'];
    panel.innerHTML = fields.map(function (k) {
      const val = v[k] || '';
      const secret = (k === 'PASSWORD' || k === 'NTLM_HASH');
      return '<label style="font-size:0.58rem;color:var(--text-muted)">' + esc(k) +
        '</label><input data-cs-var="' + esc(k) + '" type="' + (secret ? 'password' : 'text') + '" value="' + esc(val) + '" />';
    }).join('');
    if (typeof WorkspaceVars !== 'undefined') WorkspaceVars.bindCsPanel();
  }

  function renderPhaseNav() {
    const nav = document.getElementById('cs-phase-nav');
    if (!nav) return;
    nav.innerHTML = (catalog.phases || []).map(function (p) {
      const active = p.key === activePhase ? ' active' : '';
      return '<button type="button" class="cs-phase-btn' + active + '" data-phase="' + esc(p.key) + '">' +
        esc(p.icon || '') + ' ' + esc(p.label || p.key) + '</button>';
    }).join('');
    nav.querySelectorAll('.cs-phase-btn').forEach(function (btn) {
      btn.onclick = function () {
        activePhase = btn.getAttribute('data-phase');
        const phase = (catalog.phases || []).find(function (x) { return x.key === activePhase; });
        activeSub = phase && phase.subsections && phase.subsections[0] ? phase.subsections[0].key : null;
        renderAll();
      };
    });
  }

  function renderSubtabs() {
    const el = document.getElementById('cs-subtabs');
    const phase = (catalog.phases || []).find(function (x) { return x.key === activePhase; });
    if (!el || !phase) { if (el) el.innerHTML = ''; return; }
    document.getElementById('cs-phase-title').textContent = (phase.icon || '') + ' ' + (phase.label || phase.key);
    document.getElementById('cs-phase-desc').textContent = phase.key || '';
    el.innerHTML = (phase.subsections || []).map(function (s) {
      const active = s.key === activeSub ? ' active' : '';
      return '<button type="button" class="cs-subtab' + active + '" data-sub="' + esc(s.key) + '">' + esc(s.label || s.key) + '</button>';
    }).join('');
    el.querySelectorAll('.cs-subtab').forEach(function (btn) {
      btn.onclick = function () { activeSub = btn.getAttribute('data-sub'); renderCommands(); };
    });
  }

  function matchCmd(cmd) {
    const q = search.toLowerCase();
    if (q) {
      const blob = [cmd.title, cmd.tool, cmd.description, (cmd.tags || []).join(' ')].join(' ').toLowerCase();
      if (blob.indexOf(q) === -1) return false;
    }
    if (tagFilter === 'stealthy' && (cmd.tags || []).indexOf('stealthy') === -1) return false;
    if (tagFilter === 'high-value' && (cmd.tags || []).indexOf('high-value') === -1) return false;
    return true;
  }

  function renderCommands() {
    const box = document.getElementById('cs-content');
    const phase = (catalog.phases || []).find(function (x) { return x.key === activePhase; });
    const sub = phase && (phase.subsections || []).find(function (s) { return s.key === activeSub; });
    if (!box) return;
    if (!sub) { box.innerHTML = '<div class="nd-empty">Select a phase</div>'; return; }
    const cmds = (sub.commands || []).filter(matchCmd);
    box.innerHTML = cmds.map(function (c) {
      const template = c.command || '';
      const filled = subst(template);
      const action = c.admapper_action || null;
      const isPhase = action && action.type === 'phase' && action.endpoint;
      const hl = nextActionCmd && filled.indexOf(nextActionCmd.slice(0, 24)) !== -1 ? ' highlight' : '';
      const actionAttr = action ? encodeURIComponent(JSON.stringify(action)) : '';
      const templateAttr = encodeURIComponent(template);
      const tagsAttr = encodeURIComponent(JSON.stringify(c.tags || []));
      const needsAuthBtn = (c.tags || []).indexOf('requires-creds') >= 0 || (isPhase && action && action.requires_auth);
      return '<div class="cs-card' + hl + '" data-cmd-id="' + esc(c.id) + '">' +
        '<h3>' + esc(c.title) + '</h3>' +
        '<div class="meta">' + esc(c.tool || '') + ' · OPSEC ' + esc(c.opsec || '?') + ' · ' + esc((c.tags || []).join(', ')) + '</div>' +
        '<p style="font-size:0.66rem;color:var(--text-dim);margin:0 0 0.35rem">' + esc(c.description || '') + '</p>' +
        '<pre>' + esc(filled) + '</pre>' +
        '<div class="cs-card-actions">' +
        '<button type="button" data-copy="' + esc(filled) + '">Copy</button>' +
        '<button type="button" class="run"' + (needsAuthBtn ? ' data-requires-auth="1"' : '') +
        ' data-template="' + templateAttr + '" data-action="' + actionAttr + '" data-phase="' + (isPhase ? '1' : '0') +
        '" data-tags="' + tagsAttr + '">Run</button>' +
        '</div></div>';
    }).join('') || '<div class="nd-empty">No commands match filters</div>';
    box.querySelectorAll('button[data-copy]').forEach(function (btn) {
      btn.onclick = function () { copyToClipboard(btn.getAttribute('data-copy'), 'Command'); };
    });
    box.querySelectorAll('button.run').forEach(function (btn) {
      btn.onclick = function () {
        runCommand(
          btn.getAttribute('data-template'),
          btn.getAttribute('data-action'),
          btn.getAttribute('data-phase') === '1',
          btn.getAttribute('data-tags')
        );
      };
    });
  }

  function renderPaths() {
    const el = document.getElementById('cs-paths-list');
    if (!el) return;
    if (!paths.length) {
      el.innerHTML = '<div class="nd-empty">No attack paths — run paths after auth</div>';
      return;
    }
    el.innerHTML = paths.slice(0, 8).map(function (p) {
      return '<div class="path-item" data-path-id="' + esc(p.id) + '" style="cursor:pointer">' +
        '<div class="pi-route">' + esc(p.source_label || p.source) + ' → ' + esc(p.target_label || p.target) + '</div>' +
        '<div class="pi-meta">' + esc(p.id || '') + '</div></div>';
    }).join('');
    el.querySelectorAll('.path-item').forEach(function (row) {
      row.onclick = function () {
        if (typeof PathPlaybook !== 'undefined') PathPlaybook.selectPath(row.getAttribute('data-path-id'));
        setDashboardView('ops');
      };
    });
  }

  function renderAll() {
    renderPhaseNav();
    renderSubtabs();
    renderCommands();
    renderPaths();
  }

  function commandNeedsAuth(tags, action, isPhase) {
    if (isPhase && action) {
      if (action.requires_auth === false) return false;
      if (action.endpoint === '/api/scan') return false;
      if (action.endpoint === '/api/enum') return false;
      return action.requires_auth !== false;
    }
    if (tags && tags.indexOf('no-creds') >= 0) return false;
    if (tags && tags.indexOf('requires-creds') >= 0) return true;
    return false;
  }

  function runCommand(template, actionJson, isPhase, tagsJson) {
    var tags = [];
    if (tagsJson) {
      try { tags = JSON.parse(decodeURIComponent(tagsJson)); } catch (e) { tags = []; }
    }
    if (typeof WorkspaceVars !== 'undefined') {
      var r = WorkspaceVars.readiness();
      if (!r.scan_ready) {
        if (typeof termLogSemantic === 'function') {
          termLogSemantic('[!] Set DC IP in vars first', 'error');
        }
        return;
      }
    }
    let action = null;
    if (actionJson) {
      try { action = JSON.parse(decodeURIComponent(actionJson)); } catch (e) { action = null; }
    }
    if (commandNeedsAuth(tags, action, isPhase) && typeof WorkspaceVars !== 'undefined') {
      var ar = WorkspaceVars.readiness();
      if (!ar.auth_ready) {
        if (typeof termLogSemantic === 'function') {
          termLogSemantic('[!] Fill username + password/hash in vars for this command', 'error');
        }
        return;
      }
    }
    let tpl = template ? decodeURIComponent(template) : '';
    const wsVars = latestVars();
    if (isPhase && action && action.endpoint) {
      var phaseLabel = action.label || action.endpoint;
      if (typeof runOp === 'function') {
        runOp(phaseLabel, action.endpoint, Object.assign({ workspace_vars: wsVars }, action.body || {}));
        return;
      }
      fetch(action.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({ workspace_vars: wsVars }, action.body || {}))
      }).then(function (r) { return r.json(); }).then(function (data) {
        if (data.error) termLogSemantic('[!] ' + data.error, 'error');
      }).catch(function (e) { termLogSemantic('[!] ' + e, 'error'); });
      return;
    }
    const cmdTpl = (action && action.template) || tpl || '';
    if (!cmdTpl) {
      termLogSemantic('[!] no command template', 'warn');
      return;
    }
    var execLabel = cmdTpl.split('\n')[0].slice(0, 80);
    if (typeof runOp === 'function') {
      termSetRunning(execLabel);
      termLogSemantic('[*] Running: ' + execLabel, 'phase');
    }
    fetch('/api/exec', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        command_template: cmdTpl,
        workspace_vars: wsVars,
        substitute: true
      })
    }).then(function (r) { return r.json().then(function (data) {
      if (!r.ok) {
        termLogSemantic('[!] ' + (data.error || ('HTTP ' + r.status)), 'error');
        termClearRunning('error');
        return data;
      }
      return data;
    }); }).catch(function (e) {
      termLogSemantic('[!] exec failed: ' + e, 'error');
      termClearRunning('error');
    });
  }

  function saveNotes() {
    const ta = document.getElementById('cs-notes-input');
    if (!ta) return;
    const text = ta.value.trim();
    const note = { text: text, ts: Date.now() };
    fetch('/api/notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: note })
    }).then(function (r) { return r.json(); }).then(function () {
      termLogSemantic('notes saved', 'done');
    }).catch(function () {});
  }

  function openParser() {
    if (typeof OutputParser !== 'undefined' && OutputParser.open) OutputParser.open();
    setDashboardView('ops');
  }

  function toggleFilter(tag) {
    tagFilter = tagFilter === tag ? null : tag;
    document.getElementById('cs-filter-stealth').classList.toggle('on', tagFilter === 'stealthy');
    document.getElementById('cs-filter-highval').classList.toggle('on', tagFilter === 'high-value');
    renderCommands();
  }

  function init() {
    if (typeof CHEATSHEET_CATALOG !== 'undefined') catalog = CHEATSHEET_CATALOG;
    if (catalog.phases && catalog.phases.length) {
      activePhase = catalog.phases[0].key;
      activeSub = catalog.phases[0].subsections && catalog.phases[0].subsections[0]
        ? catalog.phases[0].subsections[0].key : null;
    }
    const searchEl = document.getElementById('cs-search');
    if (searchEl) searchEl.addEventListener('input', function () { search = searchEl.value; renderCommands(); });
    renderVars();
    renderAll();
  }

  function syncFromState(s) {
    if (!s) return;
    if (s.attack_paths) paths = s.attack_paths;
    const na = s.next_action || {};
    nextActionCmd = na.command || na.cli || '';
    const notes = s.findings_notes || [];
    const ta = document.getElementById('cs-notes-input');
    if (ta && notes.length) {
      ta.value = notes.map(function (n) { return n.text || ''; }).filter(Boolean).join('\n\n');
    }
    renderVars();
    renderPaths();
    renderCommands();
  }

  return {
    init: init,
    syncFromState: syncFromState,
    toggleFilter: toggleFilter,
    runCommand: runCommand,
    saveNotes: saveNotes,
    openParser: openParser,
    renderCommands: renderCommands
  };
})();

function setDashboardView(view) {
  const ops = document.getElementById('view-ops');
  const cs = document.getElementById('view-cheatsheet');
  document.querySelectorAll('.view-btn').forEach(function (btn) {
    btn.classList.toggle('active', btn.getAttribute('data-view') === view);
  });
  if (view === 'cheatsheet') {
    if (ops) ops.classList.add('hidden');
    if (cs) { cs.classList.add('active'); }
    sessionStorage.setItem('admapper_view', 'cheatsheet');
    if (typeof CheatsheetView !== 'undefined') {
      if (typeof state !== 'undefined' && state.cheatsheet_vars) {
        CheatsheetView.syncFromState(state);
      } else {
        CheatsheetView.init();
      }
    }
  } else {
    if (ops) ops.classList.remove('hidden');
    if (cs) { cs.classList.remove('active'); }
    sessionStorage.setItem('admapper_view', 'ops');
    if (typeof network !== 'undefined' && network) setTimeout(function () { network.fit(); }, 120);
  }
}

document.addEventListener('DOMContentLoaded', function () {
  const saved = sessionStorage.getItem('admapper_view');
  if (saved === 'cheatsheet') setDashboardView('cheatsheet');
});
"""


def cheatsheet_data_js() -> str:
    return f"const CHEATSHEET_CATALOG = {cheatsheet_catalog_json()};"
