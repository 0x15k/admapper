"""Feature 4 — raw tool output parser (presentation-only assets).

Slide-over drawer opened from the terminal bar. Client-side regex extracts NTLM hashes,
Kerberos roast hashes, AS-REP hashes, plain credentials, and SPNs from common
tool output (secretsdump, GetUserSPNs, Responder, nxc/CME). Selected items POST
to ``/api/import`` which merges into ``users.json`` and ``credentials.json``.
"""

from __future__ import annotations

OUTPUT_PARSER_TAB_BUTTON = ""

OUTPUT_PARSER_CSS = """
/* ── Output parser drawer ─────────────────────────────────── */
.op-drawer-backdrop{
  position:fixed;inset:0;z-index:8500;background:rgba(0,0,0,0.45);
}
.op-drawer-backdrop.hidden{display:none;}
.op-drawer{
  position:fixed;top:0;right:0;bottom:0;z-index:8501;width:min(420px,92vw);
  background:var(--bg-panel);border-left:1px solid var(--border);
  display:flex;flex-direction:column;box-shadow:-8px 0 32px rgba(0,0,0,0.45);
  transform:translateX(0);transition:transform 0.2s ease;
}
.op-drawer.hidden{display:none;}
.op-drawer-header{
  display:flex;align-items:center;justify-content:space-between;
  padding:0.65rem 0.85rem;border-bottom:1px solid var(--border);
  font-size:0.8rem;font-weight:600;
}
.op-drawer-header button{
  background:transparent;border:none;color:var(--text-dim);font-size:1.1rem;
  cursor:pointer;padding:0.15rem 0.35rem;line-height:1;
}
.op-drawer-header button:hover{color:var(--text);}
.op-drawer-body{flex:1;overflow-y:auto;padding:0.65rem 0.85rem 1rem;}
.op-hint{font-size:0.62rem;color:var(--text-dim);line-height:1.4;margin-bottom:0.45rem}
.op-textarea{
  width:100%;min-height:110px;max-height:200px;resize:vertical;
  background:var(--bg-dark);border:1px solid var(--border);color:var(--text);
  padding:0.45rem 0.5rem;border-radius:5px;font-family:var(--mono);font-size:0.66rem;
  outline:none;margin-bottom:0.4rem;
}
.op-textarea:focus{border-color:var(--accent)}
.op-toolbar{display:flex;gap:0.35rem;flex-wrap:wrap;margin-bottom:0.45rem}
.op-toolbar button{font-size:0.64rem}
.op-summary{font-size:0.62rem;color:var(--text-dim);margin-bottom:0.35rem}
.op-results{
  max-height:240px;overflow-y:auto;border:1px solid var(--border);border-radius:5px;
  background:var(--bg-dark);padding:0.25rem 0.35rem;
}
.op-item{
  display:flex;align-items:flex-start;gap:0.35rem;padding:0.3rem 0.2rem;
  border-bottom:1px solid rgba(48,54,61,0.6);font-size:0.65rem;
}
.op-item:last-child{border-bottom:none}
.op-item input[type=checkbox]{margin-top:0.15rem;accent-color:var(--accent)}
.op-item .op-body{flex:1;min-width:0}
.op-item .op-kind{
  font-size:0.55rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;
  color:var(--orange);margin-bottom:0.1rem;
}
.op-item .op-label{color:var(--text);word-break:break-all}
.op-item .op-secret{
  font-family:var(--mono);font-size:0.6rem;color:var(--text-dim);
  word-break:break-all;margin-top:0.1rem;
}
.op-empty{padding:0.5rem;text-align:center;color:var(--text-muted);font-size:0.65rem}
.op-import-row{display:flex;justify-content:space-between;align-items:center;margin-top:0.45rem;gap:0.35rem}
.op-import-row .btn-primary{font-size:0.68rem}
"""

OUTPUT_PARSER_PANE = ""

OUTPUT_PARSER_DRAWER = """
<div class="op-drawer-backdrop hidden" id="op-drawer-backdrop" onclick="OutputParser.close()"></div>
<div class="op-drawer hidden" id="op-drawer" role="dialog" aria-label="Parse tool output">
  <div class="op-drawer-header">
    <span><i class="fa-solid fa-file-import"></i> Parse output</span>
    <button type="button" onclick="OutputParser.close()" title="Close">&times;</button>
  </div>
  <div class="op-drawer-body">
    <div class="op-hint">
      Paste secretsdump, GetUserSPNs, AS-REP roast, Responder, or nxc/CME output.
      Detected hashes, creds, and SPNs appear below — check items and import into the workspace.
    </div>
    <textarea id="op-input" class="op-textarea" placeholder="Paste raw tool output here…" spellcheck="false"></textarea>
    <div class="op-toolbar">
      <button class="btn-graph-ctl" onclick="OutputParser.parse()" title="Re-run extraction">
        <i class="fa-solid fa-magnifying-glass"></i> Parse
      </button>
      <button class="btn-graph-ctl" onclick="OutputParser.selectAll(true)">Select all</button>
      <button class="btn-graph-ctl" onclick="OutputParser.selectAll(false)">Clear</button>
    </div>
    <div class="op-summary" id="op-summary">0 items detected</div>
    <div class="op-results" id="op-results">
      <div class="op-empty">Nothing parsed yet</div>
    </div>
    <div class="op-import-row">
      <span id="op-import-status" style="font-size:0.62rem;color:var(--text-dim)"></span>
      <button class="btn-graph-ctl btn-primary" onclick="OutputParser.importSelected()" id="op-import-btn">
        <i class="fa-solid fa-database"></i> Import to workspace
      </button>
    </div>
  </div>
</div>
"""

OUTPUT_PARSER_JS = r"""
/* ── Raw output parser (Feature 4) ───────────────────────── */
const OutputParser = (function () {
  let items = [];

  const KIND_LABEL = {
    ntlm: 'NTLM hash',
    password: 'Password',
    kerberos: 'Kerberoast hash',
    asrep: 'AS-REP hash',
    spn: 'SPN'
  };

  function escH(s) {
    const d = document.createElement('div');
    d.textContent = String(s == null ? '' : s);
    return d.innerHTML;
  }

  function normUser(raw) {
    let u = String(raw || '').trim();
    if (!u) return '';
    if (u.includes('\\')) u = u.split('\\').pop() || u;
    if (u.includes('@')) u = u.split('@')[0];
    return u;
  }

  function keyFor(it) {
    return [it.kind, it.username || '', it.secret || '', it.spn || ''].join('|');
  }

  function addItem(bucket, seen, it) {
    if (!it || !it.secret) return;
    const k = keyFor(it);
    if (seen.has(k)) return;
    seen.add(k);
    bucket.push(it);
  }

  function parseText(text) {
    const out = [];
    const seen = new Set();
    const lines = String(text || '').split(/\r?\n/);

    const ntlmLine = /^(?:([^\\:\s]+)\\)?([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})(?:::)?\s*$/;
    const ntlmBare = /\b([a-fA-F0-9]{32}):([a-fA-F0-9]{32})\b/g;
    const krbTgs = /\$krb5tgs\$[^\s'"]+/gi;
    const krbAsrep = /\$krb5asrep\$[^\s'"]+/gi;
    const cmePwn = /(?:\[+\]|\(Pwn3d!\))\s*(?:([A-Za-z0-9_.-]+)\\)?([A-Za-z0-9_.$-]+)\s*[:=]\s*([^\s'"]{3,})/gi;
    const userPass = /(?:^|\s)(?:([A-Za-z0-9_.-]+)\\)?([A-Za-z0-9_.$-]{2,}):([^:\s'"]{4,})(?:\s|$)/g;
    const spnRow = /^([A-Za-z][A-Za-z0-9._-]*\/[^\s]+)\s+([A-Za-z0-9_.$-]+)\s*$/;
    const spnToken = /\b([A-Za-z][A-Za-z0-9._-]*\/[A-Za-z0-9._-]+(?::\d+)?(?:\/[A-Za-z0-9._-]+)?)\b/g;

    lines.forEach(function (line) {
      const trimmed = line.trim();
      if (!trimmed) return;

      let m = trimmed.match(ntlmLine);
      if (m) {
        const domain = m[1] || '';
        const user = normUser(m[2]);
        const nthash = m[5].toLowerCase();
        if (user && nthash !== '31d6cfe0d16ae931b73c59d7e0c089c0') {
          addItem(out, seen, { kind: 'ntlm', username: user, secret: nthash, domain: domain, selected: true });
        }
        return;
      }

      m = trimmed.match(spnRow);
      if (m) {
        addItem(out, seen, { kind: 'spn', username: normUser(m[2]), secret: m[1], spn: m[1], selected: true });
        return;
      }
    });

    const full = String(text || '');

    let match;
    while ((match = krbTgs.exec(full)) !== null) {
      const hash = match[0];
      const userM = hash.match(/\$krb5tgs\$[0-9]+\$\*([^$*]+)/i);
      const user = userM ? normUser(userM[1]) : '';
      addItem(out, seen, { kind: 'kerberos', username: user, secret: hash, selected: true });
    }
    while ((match = krbAsrep.exec(full)) !== null) {
      const hash = match[0];
      const userM = hash.match(/\$krb5asrep\$[0-9]+\$([^$]+)@/i);
      const user = userM ? normUser(userM[1]) : '';
      addItem(out, seen, { kind: 'asrep', username: user, secret: hash, selected: true });
    }

    while ((match = cmePwn.exec(full)) !== null) {
      const domain = match[1] || '';
      const user = normUser(match[2]);
      const pass = match[3];
      if (user && pass && !pass.startsWith('$krb5')) {
        addItem(out, seen, { kind: 'password', username: user, secret: pass, domain: domain, selected: true });
      }
    }

    while ((match = userPass.exec(full)) !== null) {
      const domain = match[1] || '';
      const user = normUser(match[2]);
      const pass = match[3];
      if (!user || !pass) continue;
      if (/^[a-fA-F0-9]{32}$/.test(pass)) continue;
      if (pass.startsWith('$krb5')) continue;
      if (user.toLowerCase() === 'smb' || user.toLowerCase() === 'http') continue;
      addItem(out, seen, { kind: 'password', username: user, secret: pass, domain: domain, selected: true });
    }

    while ((match = ntlmBare.exec(full)) !== null) {
      const nthash = match[2].toLowerCase();
      if (nthash === '31d6cfe0d16ae931b73c59d7e0c089c0') continue;
      addItem(out, seen, { kind: 'ntlm', username: '', secret: nthash, selected: true });
    }

    while ((match = spnToken.exec(full)) !== null) {
      const spn = match[1];
      if (spn.indexOf('/') === -1) continue;
      addItem(out, seen, { kind: 'spn', username: '', secret: spn, spn: spn, selected: true });
    }

    return out;
  }

  function render() {
    const list = document.getElementById('op-results');
    const summary = document.getElementById('op-summary');
    if (!list) return;
    if (summary) summary.textContent = items.length + ' item(s) detected';
    if (!items.length) {
      list.innerHTML = '<div class="op-empty">No hashes, creds, or SPNs found — try pasting more output</div>';
      return;
    }
    let html = '';
    items.forEach(function (it, idx) {
      const label = (it.username ? escH(it.username) : '(unknown user)') +
        (it.domain ? ' <span style="color:var(--text-muted)">@ ' + escH(it.domain) + '</span>' : '');
      const secret = it.kind === 'spn' ? (it.spn || it.secret) : it.secret;
      const short = secret.length > 96 ? secret.slice(0, 96) + '…' : secret;
      html += '<label class="op-item">' +
        '<input type="checkbox" data-op-idx="' + idx + '"' + (it.selected !== false ? ' checked' : '') + '>' +
        '<div class="op-body">' +
          '<div class="op-kind">' + escH(KIND_LABEL[it.kind] || it.kind) + '</div>' +
          '<div class="op-label">' + label + '</div>' +
          '<div class="op-secret">' + escH(short) + '</div>' +
        '</div></label>';
    });
    list.innerHTML = html;
    list.querySelectorAll('input[type=checkbox]').forEach(function (cb) {
      cb.onchange = function () {
        const i = parseInt(cb.dataset.opIdx, 10);
        if (!isNaN(i) && items[i]) items[i].selected = cb.checked;
      };
    });
  }

  function parse() {
    const el = document.getElementById('op-input');
    items = parseText(el ? el.value : '');
    render();
    const status = document.getElementById('op-import-status');
    if (status) status.textContent = '';
  }

  function selectAll(on) {
    items.forEach(function (it) { it.selected = !!on; });
    render();
  }

  function importSelected() {
    const selected = items.filter(function (it) { return it.selected !== false; });
    if (!selected.length) {
      if (typeof termLogSemantic === 'function') termLogSemantic('No parser items selected', 'error');
      return;
    }
    const btn = document.getElementById('op-import-btn');
    const status = document.getElementById('op-import-status');
    if (btn) btn.disabled = true;
    if (status) status.textContent = 'Importing…';
    if (typeof apiPost !== 'function') {
      if (status) status.textContent = 'API unavailable';
      if (btn) btn.disabled = false;
      return;
    }
    apiPost('/api/import', { items: selected }).then(function (r) { return r.json(); }).then(function (d) {
      if (btn) btn.disabled = false;
      if (d && d.ok) {
        const msg = 'Imported ' + (d.credentials_added || 0) + ' cred(s), ' + (d.users_merged || 0) + ' user update(s)';
        if (status) status.textContent = msg;
        if (typeof termLogSemantic === 'function') termLogSemantic(msg, 'done');
        if (typeof refreshState === 'function') refreshState();
      } else {
        const err = (d && d.error) ? d.error : 'Import failed';
        if (status) status.textContent = err;
        if (typeof termLogSemantic === 'function') termLogSemantic(err, 'error');
      }
    }).catch(function (e) {
      if (btn) btn.disabled = false;
      if (status) status.textContent = String(e);
      if (typeof termLogSemantic === 'function') termLogSemantic('Import request failed', 'error');
    });
  }

  function open() {
    const drawer = document.getElementById('op-drawer');
    const backdrop = document.getElementById('op-drawer-backdrop');
    if (drawer) drawer.classList.remove('hidden');
    if (backdrop) backdrop.classList.remove('hidden');
    const el = document.getElementById('op-input');
    if (el) {
      var prefill = (typeof window.termLastOutput === 'function') ? window.termLastOutput() : '';
      if (prefill && !el.value.trim()) el.value = prefill;
      setTimeout(function () { el.focus(); }, 80);
    }
  }

  function close() {
    const drawer = document.getElementById('op-drawer');
    const backdrop = document.getElementById('op-drawer-backdrop');
    if (drawer) drawer.classList.add('hidden');
    if (backdrop) backdrop.classList.add('hidden');
  }

  function init() {
    const el = document.getElementById('op-input');
    if (el) {
      el.addEventListener('input', function () {
        window.clearTimeout(el._opTimer);
        el._opTimer = window.setTimeout(parse, 400);
      });
    }
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') close();
    });
  }

  return { init: init, open: open, close: close, parse: parse, selectAll: selectAll, importSelected: importSelected, parseText: parseText };
})();
"""
