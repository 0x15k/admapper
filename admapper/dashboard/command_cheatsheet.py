"""Feature 2 — live command cheatsheet (presentation-only assets).

Renders a "Commands" tab in the dashboard right panel. Commands are sourced
*directly* from ``admapper.guides.catalog.MANUAL_GUIDE_CATALOG`` (serialized to
JSON at HTML-build time) so there is a single command database — the JS never
maintains its own copy.

Variable substitution: the operator sets DOMAIN / DC_IP / USER / PASS / HASH
once (prefilled from the workspace via /api/state) and every command's
``<DOMAIN>``, ``<DC_IP>``, ``<DC>``, ``<BASE_DN>``, ``<USER>``, ``<PASS>``,
``<HASH>``, ``<workspace>`` tokens fill live. Ctrl+K opens a fuzzy palette.

Presentation-only: imports the static guide catalog (read-only data), nothing
stateful, no writes — consistent with the dashboard separation-of-concerns rule.
"""

from __future__ import annotations

import json

from admapper.guides.catalog import MANUAL_GUIDE_CATALOG


def command_catalog_json() -> str:
    """Serialize the manual guide catalog to JSON for the browser.

    Single source of truth: the JS cheatsheet is generated from this, never a
    hand-maintained duplicate.
    """
    payload = [
        {
            "key": g.key,
            "title": g.title,
            "summary": g.summary,
            "mitre": g.mitre_id or "",
            "tools": list(g.tools),
            "prerequisites": list(g.prerequisites),
            "commands": list(g.commands),
            "next_steps": list(g.next_steps),
        }
        for g in MANUAL_GUIDE_CATALOG.values()
    ]
    # Escape '<' so an embedded "</script" can never terminate the host script.
    return json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")


# Sidebar tab button injected into the .sb-tabs bar.
COMMAND_TAB_BUTTON = (
    '<button class="sb-tab" data-tab="commands" onclick="setSidebarTab(\'commands\')" '
    'title="Command cheatsheet with live variable substitution (Ctrl+K to search)">'
    '<i class="fa-solid fa-terminal"></i> Commands</button>'
)

# Injected inside the dashboard <style> block.
COMMAND_CSS = """
/* ── Sidebar tabs (Features 2 & 4) ───────────────────────── */
.sb-tabs{
  display:flex;gap:0.2rem;padding:0.4rem 0.5rem;position:sticky;top:0;z-index:6;
  background:var(--bg-panel);border-bottom:1px solid var(--border);flex-wrap:wrap;
}
.sb-tab{
  background:var(--bg-card);border:1px solid var(--border);color:var(--text-dim);
  padding:0.3rem 0.55rem;border-radius:4px;font-size:0.66rem;font-weight:600;
  cursor:pointer;transition:all 0.15s;display:flex;align-items:center;gap:0.3rem;
}
.sb-tab:hover{background:var(--bg-hover);color:var(--text)}
.sb-tab.active{background:var(--accent);border-color:var(--accent);color:#fff}
.sb-pane{display:none}
.sb-pane.active{display:block}

/* ── Command cheatsheet (Feature 2) ──────────────────────── */
.cc-vars{
  display:grid;grid-template-columns:1fr 1fr;gap:0.4rem;padding:0.75rem 0.85rem;
  border-bottom:1px solid var(--border);
}
.cc-field{display:flex;flex-direction:column;gap:0.15rem}
.cc-field.cc-wide{grid-column:1 / -1}
.cc-field label{
  font-size:0.58rem;text-transform:uppercase;letter-spacing:0.06em;
  color:var(--text-dim);font-weight:700;
}
.cc-field input{
  background:var(--bg-dark);border:1px solid var(--border);color:var(--text);
  padding:0.3rem 0.4rem;border-radius:4px;font-family:var(--mono);
  font-size:0.7rem;outline:none;min-width:0;
}
.cc-field input:focus{border-color:var(--accent)}
.cc-field input::placeholder{color:var(--text-muted)}
.cc-search-wrap{padding:0.5rem 0.85rem;position:relative}
.cc-search-wrap i{
  position:absolute;left:1.15rem;top:50%;transform:translateY(-50%);
  color:var(--text-muted);font-size:0.7rem;
}
.cc-search-wrap input{
  width:100%;background:var(--bg-dark);border:1px solid var(--border);
  color:var(--text);padding:0.35rem 0.5rem 0.35rem 1.65rem;border-radius:5px;
  font-size:0.72rem;outline:none;
}
.cc-search-wrap input:focus{border-color:var(--accent)}
.cc-kbd{
  position:absolute;right:1.1rem;top:50%;transform:translateY(-50%);
  font-size:0.55rem;color:var(--text-muted);border:1px solid var(--border);
  border-radius:3px;padding:0.05rem 0.3rem;font-family:var(--mono);
}
.cc-list{padding:0 0.6rem 1rem;overflow-y:auto}
.cc-guide{margin-bottom:0.6rem}
.cc-guide-head{
  display:flex;justify-content:space-between;align-items:baseline;gap:0.4rem;
  padding:0.4rem 0.25rem 0.25rem;border-bottom:1px solid var(--border);margin-bottom:0.3rem;
}
.cc-guide-title{font-size:0.7rem;font-weight:700;color:var(--text)}
.cc-guide-mitre{font-size:0.56rem;color:var(--text-muted);font-family:var(--mono);white-space:nowrap}
.cc-cmd{
  background:#0d1117;border:1px solid var(--border);border-radius:4px;
  padding:0.35rem 0.45rem;margin-bottom:0.25rem;display:flex;align-items:center;
  justify-content:space-between;gap:0.4rem;cursor:pointer;transition:border-color 0.1s;
}
.cc-cmd:hover{border-color:var(--border-light)}
.cc-cmd code{
  background:none;font-family:var(--mono);font-size:0.66rem;color:var(--text);
  white-space:pre-wrap;word-break:break-all;flex:1;line-height:1.4;
}
.cc-cmd .copy-icon{color:var(--text-muted);flex-shrink:0}
.cc-cmd:hover .copy-icon{color:var(--text-dim)}
.cmd-ph{color:var(--yellow);font-weight:600}
.cmd-tok{color:var(--cyan)}
.cc-empty{padding:1rem 0.85rem;color:var(--text-muted);font-size:0.72rem;font-style:italic}

/* ── Ctrl+K command palette (Feature 2) ──────────────────── */
.cc-palette{
  position:fixed;inset:0;z-index:50;display:none;
  background:rgba(1,4,9,0.6);backdrop-filter:blur(2px);
  align-items:flex-start;justify-content:center;padding-top:12vh;
}
.cc-palette.open{display:flex}
.cc-palette-box{
  width:min(680px,92vw);max-height:64vh;display:flex;flex-direction:column;
  background:var(--bg-panel);border:1px solid var(--border-light);border-radius:10px;
  box-shadow:0 16px 48px rgba(0,0,0,0.6);overflow:hidden;
}
.cc-palette-box input{
  background:var(--bg-dark);border:none;border-bottom:1px solid var(--border);
  color:var(--text);padding:0.7rem 0.9rem;font-size:0.85rem;outline:none;
  font-family:var(--mono);
}
.cc-palette-results{overflow-y:auto;padding:0.35rem}
.cc-presult{
  padding:0.4rem 0.55rem;border-radius:5px;cursor:pointer;display:flex;
  flex-direction:column;gap:0.1rem;
}
.cc-presult.sel,.cc-presult:hover{background:var(--bg-hover)}
.cc-presult .pr-cmd{font-family:var(--mono);font-size:0.72rem;color:var(--text);word-break:break-all}
.cc-presult .pr-meta{font-size:0.58rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.04em}
.cc-palette-foot{
  padding:0.35rem 0.7rem;border-top:1px solid var(--border);font-size:0.6rem;
  color:var(--text-muted);display:flex;gap:1rem;
}
"""

# The Commands sidebar pane (Feature 2).
COMMAND_PANE = """
<div class="sb-pane" id="sb-pane-commands">
  <div class="cc-vars">
    <div class="cc-field"><label>Domain</label><input id="cc-domain" placeholder="corp.local" autocomplete="off" spellcheck="false"/></div>
    <div class="cc-field"><label>DC / IP</label><input id="cc-dc" placeholder="10.0.0.1" autocomplete="off" spellcheck="false"/></div>
    <div class="cc-field"><label>Username</label><input id="cc-user" placeholder="jdoe" autocomplete="off" spellcheck="false"/></div>
    <div class="cc-field"><label>Password</label><input id="cc-pass" placeholder="Winter2026!" type="password" autocomplete="off" spellcheck="false"/></div>
    <div class="cc-field cc-wide"><label>NTLM hash</label><input id="cc-hash" placeholder="aad3b...:nthash" type="password" autocomplete="off" spellcheck="false"/></div>
    <div class="cc-field"><label>Attacker IP</label><input id="cc-attacker" placeholder="192.168.1.50" autocomplete="off" spellcheck="false"/></div>
    <div class="cc-field"><label>CA name</label><input id="cc-ca" placeholder="corp-CA" autocomplete="off" spellcheck="false"/></div>
    <div class="cc-field cc-wide"><label>Template</label><input id="cc-template" placeholder="ESC1 template" autocomplete="off" spellcheck="false"/></div>
  </div>
  <div class="cc-search-wrap">
    <i class="fa-solid fa-magnifying-glass"></i>
    <input id="cc-search" placeholder="Filter commands..." autocomplete="off" spellcheck="false"/>
    <span class="cc-kbd">Ctrl K</span>
  </div>
  <div class="cc-list" id="cc-list"></div>
</div>
"""

# The Ctrl+K palette overlay (Feature 2) — lives at body level.
COMMAND_PALETTE = """
<div class="cc-palette" id="cc-palette">
  <div class="cc-palette-box" onclick="event.stopPropagation()">
    <input id="cc-palette-input" placeholder="Search all commands (variables auto-filled)..." autocomplete="off" spellcheck="false"/>
    <div class="cc-palette-results" id="cc-palette-results"></div>
    <div class="cc-palette-foot"><span>↑↓ navigate</span><span>↵ copy</span><span>esc close</span></div>
  </div>
</div>
"""

# Injected into the dashboard <script> block, before the init triggers.
# Expects `const COMMAND_CATALOG = [...]` to be defined just above this block.
COMMAND_JS = r"""
/* ── Sidebar tabs (Features 2 & 4) ───────────────────────── */
function setSidebarTab(name) {
  document.querySelectorAll('.sb-pane').forEach(function (p) {
    p.classList.toggle('active', p.id === 'sb-pane-' + name);
  });
  document.querySelectorAll('.sb-tab').forEach(function (b) {
    b.classList.toggle('active', b.dataset.tab === name);
  });
}

/* ── Command cheatsheet w/ live variable substitution (Feature 2) ─ */
const CommandCheatsheet = (function () {
  // Flat list of {guideKey, guideTitle, mitre, raw} built from COMMAND_CATALOG.
  const items = [];
  const dirty = {};
  let workspace = '';
  let paletteSel = 0;
  let paletteRows = [];

  function escH(s) {
    const d = document.createElement('div');
    d.textContent = String(s == null ? '' : s);
    return d.innerHTML;
  }

  function buildItems() {
    const cat = (typeof COMMAND_CATALOG !== 'undefined') ? COMMAND_CATALOG : [];
    cat.forEach(function (g) {
      (g.commands || []).forEach(function (raw) {
        items.push({ guideKey: g.key, guideTitle: g.title, mitre: g.mitre || '', raw: raw });
      });
    });
    const phased = (typeof CHEATSHEET_CATALOG !== 'undefined') ? CHEATSHEET_CATALOG : { phases: [] };
    (phased.phases || []).forEach(function (phase) {
      (phase.subsections || []).forEach(function (sub) {
        (sub.commands || []).forEach(function (cmd) {
          items.push({
            guideKey: 'cs:' + (cmd.id || cmd.title),
            guideTitle: (phase.label || phase.key) + ' / ' + (sub.label || sub.key),
            mitre: '',
            raw: cmd.command || '',
            title: cmd.title || ''
          });
        });
      });
    });
  }

  function val(id) {
    const el = document.getElementById('cc-' + id);
    return el ? el.value.trim() : '';
  }

  function baseDn(domain) {
    if (!domain) return '';
    return domain.split('.').filter(Boolean).map(function (p) { return 'DC=' + p; }).join(',');
  }

  function vars() {
    if (typeof WorkspaceVars !== 'undefined') {
      const e = WorkspaceVars.toSubstExtra();
      return {
        domain: e.domain,
        dc: e.dc,
        baseDn: baseDn(e.domain),
        user: e.user,
        pass: e.pass,
        hash: e.hash,
        workspace: e.workspace || workspace,
        attackerIp: e.attackerIp,
        caName: e.caName,
        template: e.template
      };
    }
    const domain = val('domain');
    const dc = val('dc');
    return {
      domain: domain,
      dc: dc,
      baseDn: baseDn(domain),
      user: val('user'),
      pass: val('pass'),
      hash: val('hash'),
      workspace: workspace,
      attackerIp: val('attacker') || '',
      caName: val('ca') || '',
      template: val('template') || ''
    };
  }

  // Substitute angle-bracket and brace tokens; unknown placeholders stay literal.
  function subst(raw, v) {
    const map = {
      '<DOMAIN>': v.domain, '<DC_IP>': v.dc, '<DC>': v.dc, '<BASE_DN>': v.baseDn,
      '<USER>': v.user, '<PASS>': v.pass, '<PASSWORD>': v.pass,
      '<HASH>': v.hash, '<NTLM>': v.hash, '<workspace>': v.workspace,
      '{DOMAIN}': v.domain, '{DC_IP}': v.dc, '{USERNAME}': v.user,
      '{PASSWORD}': v.pass, '{NTLM_HASH}': v.hash, '{ATTACKER_IP}': v.attackerIp || '',
      '{CA_NAME}': v.caName || '', '{TEMPLATE}': v.template || ''
    };
    let out = raw.replace(/<[A-Za-z0-9_]+>/g, function (tok) {
      const repl = map[tok];
      return (repl !== undefined && repl !== '') ? repl : tok;
    });
    out = out.replace(/\{[A-Za-z0-9_]+\}/g, function (tok) {
      const repl = map[tok];
      return (repl !== undefined && repl !== '') ? repl : tok;
    });
    return out;
  }

  // Escape for HTML then highlight remaining <PLACEHOLDERS>.
  function fmt(cmd) {
    return escH(cmd).replace(/&lt;([A-Za-z0-9_]+)&gt;/g, '<span class="cmd-ph">&lt;$1&gt;</span>');
  }

  function setIfClean(id, value) {
    const el = document.getElementById('cc-' + id);
    if (!el || dirty[id]) return;
    if (value && el.value !== value) el.value = value;
  }

  function syncFromState(s) {
    if (!s) return;
    const meta = s.meta || {};
    workspace = meta.workspace || workspace;
    if (typeof WorkspaceVars !== 'undefined') {
      render();
      return;
    }
    const cv = s.cheatsheet_vars || {};
    const player = s.player || {};
    const domain = cv.DOMAIN || ((meta.domain && meta.domain !== '???') ? meta.domain : '');
    const dc = cv.DC_IP || meta.dc_ip || meta.dc_host || '';
    const user = cv.USERNAME || player.pivot || (((s.creds || [])[0]) || {}).user || '';
    const ulow = user.toLowerCase().replace(/\$+$/, '');

    let pass = cv.PASSWORD || '';
    (s.clues || []).forEach(function (c) {
      if (pass) return;
      if (!user || String(c.user || '').toLowerCase() === user.toLowerCase()) pass = c.string || '';
    });
    if (!pass && (s.clues || []).length) pass = s.clues[0].string || '';

    let hash = cv.NTLM_HASH || '';
    (s.pth_sessions || []).forEach(function (p) {
      if (hash) return;
      const acc = String(p.account || '').toLowerCase().replace(/\$+$/, '');
      if (!user || acc === ulow) hash = p.nthash || '';
    });
    if (!hash && (s.pth_sessions || []).length) hash = s.pth_sessions[0].nthash || '';

    setIfClean('domain', domain);
    setIfClean('dc', dc);
    setIfClean('user', user);
    setIfClean('pass', pass);
    setIfClean('hash', hash);
    if (document.getElementById('cc-attacker')) setIfClean('attacker', cv.ATTACKER_IP || '');
    if (document.getElementById('cc-ca')) setIfClean('ca', cv.CA_NAME || '');
    if (document.getElementById('cc-template')) setIfClean('template', cv.TEMPLATE || '');
    render();
  }

  function render() {
    const list = document.getElementById('cc-list');
    if (!list) return;
    const v = vars();
    const q = val('search').toLowerCase();
    const byGuide = {};
    const order = [];
    items.forEach(function (it) {
      const filled = subst(it.raw, v);
      const label = it.title || it.guideTitle;
      if (q && (filled.toLowerCase().indexOf(q) === -1) && (label.toLowerCase().indexOf(q) === -1)) return;
      if (!byGuide[it.guideKey]) { byGuide[it.guideKey] = { title: it.guideTitle, mitre: it.mitre, cmds: [] }; order.push(it.guideKey); }
      byGuide[it.guideKey].cmds.push(filled);
    });

    if (!order.length) { list.innerHTML = '<div class="cc-empty">No commands match your filter.</div>'; return; }

    let html = '';
    order.forEach(function (k) {
      const g = byGuide[k];
      html += '<div class="cc-guide"><div class="cc-guide-head">' +
        '<span class="cc-guide-title">' + escH(g.title) + '</span>' +
        (g.mitre ? '<span class="cc-guide-mitre">' + escH(g.mitre) + '</span>' : '') +
        '</div>';
      g.cmds.forEach(function (cmd) {
        html += '<div class="cc-cmd" data-copy-val="' + escH(cmd) + '" data-copy-label="Command" title="Click to copy">' +
          '<code>' + fmt(cmd) + '</code><i class="fa-regular fa-copy copy-icon"></i></div>';
      });
      html += '</div>';
    });
    list.innerHTML = html;
  }

  /* ── Ctrl+K fuzzy palette ──────────────────────────────── */
  function fuzzy(needle, hay) {
    needle = needle.toLowerCase(); hay = hay.toLowerCase();
    let i = 0, j = 0, score = 0, streak = 0;
    while (i < needle.length && j < hay.length) {
      if (needle[i] === hay[j]) { i++; streak++; score += streak; } else { streak = 0; }
      j++;
    }
    return i === needle.length ? score : -1;
  }

  function paletteRender() {
    const box = document.getElementById('cc-palette-results');
    const q = (document.getElementById('cc-palette-input') || {}).value || '';
    const v = vars();
    let rows = items.map(function (it) {
      const filled = subst(it.raw, v);
      const score = q ? fuzzy(q, filled + ' ' + it.guideTitle) : 0;
      return { filled: filled, guide: it.guideTitle, score: score };
    });
    if (q) rows = rows.filter(function (r) { return r.score >= 0; }).sort(function (a, b) { return b.score - a.score; });
    rows = rows.slice(0, 50);
    paletteRows = rows;
    if (paletteSel >= rows.length) paletteSel = 0;
    box.innerHTML = rows.map(function (r, idx) {
      return '<div class="cc-presult' + (idx === paletteSel ? ' sel' : '') + '" data-idx="' + idx + '">' +
        '<div class="pr-cmd">' + fmt(r.filled) + '</div>' +
        '<div class="pr-meta">' + escH(r.guide) + '</div></div>';
    }).join('') || '<div class="cc-empty">No matches.</div>';
  }

  function paletteCopy(idx) {
    const r = paletteRows[idx];
    if (!r) return;
    if (typeof copyToClipboard === 'function') copyToClipboard(r.filled, 'Command');
    closePalette();
  }

  function openPalette() {
    const p = document.getElementById('cc-palette');
    if (!p) return;
    paletteSel = 0;
    p.classList.add('open');
    paletteRender();
    const inp = document.getElementById('cc-palette-input');
    if (inp) { inp.value = ''; inp.focus(); }
  }

  function closePalette() {
    const p = document.getElementById('cc-palette');
    if (p) p.classList.remove('open');
  }

  function init() {
    buildItems();
    if (typeof WorkspaceVars !== 'undefined') {
      WorkspaceVars.bindCcInputs();
    } else {
      ['domain', 'dc', 'user', 'pass', 'hash', 'attacker', 'ca', 'template'].forEach(function (id) {
        const el = document.getElementById('cc-' + id);
        if (!el) return;
        el.addEventListener('input', function () { dirty[id] = true; render(); });
      });
    }
    const search = document.getElementById('cc-search');
    if (search) search.addEventListener('input', render);

    const palInput = document.getElementById('cc-palette-input');
    if (palInput) palInput.addEventListener('input', function () { paletteSel = 0; paletteRender(); });
    const palResults = document.getElementById('cc-palette-results');
    if (palResults) palResults.addEventListener('click', function (e) {
      const row = e.target.closest('[data-idx]');
      if (row) paletteCopy(parseInt(row.dataset.idx, 10));
    });
    const pal = document.getElementById('cc-palette');
    if (pal) pal.addEventListener('click', closePalette);

    document.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        const p = document.getElementById('cc-palette');
        if (p && p.classList.contains('open')) closePalette(); else openPalette();
        return;
      }
      const p = document.getElementById('cc-palette');
      if (!p || !p.classList.contains('open')) return;
      if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); paletteSel = Math.min(paletteSel + 1, paletteRows.length - 1); paletteRender(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); paletteSel = Math.max(paletteSel - 1, 0); paletteRender(); }
      else if (e.key === 'Enter') { e.preventDefault(); paletteCopy(paletteSel); }
    });

    render();
  }

  return { init: init, syncFromState: syncFromState, openPalette: openPalette, render: render, substitute: function (cmd, extra) {
    const v = vars();
    if (extra) {
      Object.keys(extra).forEach(function (k) {
        if (extra[k]) {
          if (k === 'domain') v.domain = extra[k];
          else if (k === 'dc' || k === 'dc_ip') v.dc = extra[k];
          else if (k === 'user') v.user = extra[k];
          else if (k === 'pass' || k === 'password') v.pass = extra[k];
          else if (k === 'hash') v.hash = extra[k];
          else if (k === 'workspace') v.workspace = extra[k];
        }
      });
      if (v.domain) v.baseDn = baseDn(v.domain);
    }
    return subst(cmd, v);
  }};
})();

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', CommandCheatsheet.init);
} else {
  CommandCheatsheet.init();
}
"""
