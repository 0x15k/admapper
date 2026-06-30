"""Feature 1 — SharpHound .zip import overlay (presentation-only assets).

Holds the client-side CSS / HTML / JS for the dashboard's SharpHound import
feature. Everything here is a static string injected into the dashboard SPA by
``dashboard_html.build_dashboard_html``.

Design notes (kept here so dashboard_html stays readable):
- Parsing is 100% client-side via JSZip (CDN) — no backend route, ``graph.json``
  is never replaced. The parsed graph is overlaid as a *second* vis.js layer.
- Overlay nodes use a different shape (diamond) and type-colored borders so they
  are visually distinct from the icon-shaped nodes built from ``graph.json``.
- IDs are namespaced (``sh:`` / ``she:``) so they can never collide with the
  live graph and survive ``refreshState()`` re-renders.

This module is presentation-only and imports nothing from the rest of ADMapper,
per the dashboard separation-of-concerns rule.
"""

from __future__ import annotations

# JSZip is loaded from CDN (same library CrownHunter uses) — added to <head>.
SHARPHOUND_HEAD = (
    '<script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/'
    'jszip.min.js"></script>'
)

# Injected inside the dashboard <style> block.
SHARPHOUND_CSS = """
/* ── SharpHound import overlay (Feature 1) ───────────────── */
.sh-dropzone{
  position:absolute;inset:0;z-index:8;display:none;
  align-items:center;justify-content:center;
  background:rgba(13,17,23,0.82);backdrop-filter:blur(2px);
  border:2px dashed var(--purple);border-radius:8px;pointer-events:none;
}
.sh-dropzone.active{display:flex}
.sh-dropzone-inner{
  text-align:center;color:var(--purple);font-weight:600;font-size:0.95rem;
  display:flex;flex-direction:column;gap:0.5rem;align-items:center;
}
.sh-dropzone-inner i{font-size:2.4rem}
.btn-graph-ctl.sh-on{background:var(--purple);border-color:var(--purple);color:#0d1117}
#sh-count{
  background:rgba(0,0,0,0.25);border-radius:6px;padding:0 0.25rem;
  font-size:0.6rem;margin-left:0.1rem;
}
"""

# Injected into the graph-controls-group button row.
SHARPHOUND_CONTROLS = """
<button class="btn-graph-ctl" onclick="SharpHoundImport.collectViaShell()" title="Upload bundled SharpHound.exe to the active reverse shell, collect as current user, import overlay"><i class="fa-solid fa-crosshairs"></i> SH Collect</button>
<button class="btn-graph-ctl" onclick="document.getElementById('sh-file-input').click()" title="Import a SharpHound .zip and overlay it on the live graph (parsed in-browser)"><i class="fa-solid fa-file-import"></i> SharpHound</button>
<button class="btn-graph-ctl" id="sh-toggle-btn" onclick="SharpHoundImport.toggle()" style="display:none" title="Toggle the imported SharpHound overlay layer"><i class="fa-regular fa-eye"></i> SH Layer <span id="sh-count">0</span></button>
"""

# Injected into the graph-area, right after the network canvas.
SHARPHOUND_DROPZONE = """
<div id="sh-dropzone" class="sh-dropzone">
  <div class="sh-dropzone-inner">
    <i class="fa-solid fa-file-zipper"></i>
    <div>Drop SharpHound .zip to overlay on the graph</div>
    <div style="font-size:0.7rem;color:var(--text-dim);font-weight:400">Parsed in-browser · graph.json stays untouched</div>
  </div>
</div>
<input id="sh-file-input" type="file" accept=".zip,application/zip" style="display:none"/>
"""

# Injected into the graph legend.
SHARPHOUND_LEGEND = (
    '<div class="legend-item" id="sh-legend" style="display:none;color:#d2a8ff">'
    '<i class="fa-solid fa-gem"></i> SharpHound (imported)</div>'
)

# Injected into the dashboard <script> block, before the init triggers.
# Raw string so JS escapes (e.g. \\n, regex \\.) survive verbatim.
SHARPHOUND_JS = r"""
/* ── SharpHound ZIP import overlay (Feature 1) ─────────────
* Parses a SharpHound / BloodHound-CE .zip entirely client-side (JSZip) and
* overlays the parsed graph on top of the live vis.js network as a visually
* distinct second layer. graph.json is NEVER replaced. Hooked into
* setGraphFilter() via SharpHoundImport.overlayFor() so it survives refreshes.
*/
const SharpHoundImport = (function () {
  const NODE_STYLE = {
    user:      { border: '#d2a8ff' },
    computer:  { border: '#79c0ff' },
    group:     { border: '#f0a35e' },
    domain:    { border: '#f85149' },
    gpo:       { border: '#56d4dd' },
    ou:        { border: '#8b949e' },
    container: { border: '#8b949e' },
    base:      { border: '#8957e5' }
  };
  const MAX_NODES = 2000;
  const MAX_EDGES = 4000;

  let visNodes = [];
  let visEdges = [];
  let visible = true;

  function emit(text, kind) {
    if (typeof termLogSemantic === 'function') termLogSemantic(text, kind || 'log');
  }

  function typeFromName(name) {
    const n = String(name || '').toLowerCase();
    if (n.indexOf('computers') !== -1) return 'computer';
    if (n.indexOf('users') !== -1) return 'user';
    if (n.indexOf('groups') !== -1) return 'group';
    if (n.indexOf('domains') !== -1) return 'domain';
    if (n.indexOf('gpos') !== -1) return 'gpo';
    if (n.indexOf('ous') !== -1) return 'ou';
    if (n.indexOf('containers') !== -1) return 'container';
    return 'base';
  }

  function shortLabel(s) {
    let label = String(s || '');
    if (label.length > 22) label = label.slice(0, 20) + '...';
    return label;
  }

  function asArray(v) { return Array.isArray(v) ? v : []; }

  /* Parse one BloodHound JSON object file into {nodes, edges} fragments.
  * Robust to BloodHound legacy + CE schema variants. */
  function parseFile(fileName, json) {
    const out = { nodes: [], edges: [] };
    const metaType = json && json.meta && json.meta.type ? json.meta.type : fileName;
    const fallbackType = typeFromName(metaType);
    const items = (json && Array.isArray(json.data)) ? json.data : [];
    items.forEach(function (obj) {
      if (!obj) return;
      const props = obj.Properties || {};
      const id = obj.ObjectIdentifier || obj.ObjectID || props.objectid;
      if (!id) return;
      const sid = String(id);
      const name = props.name || props.distinguishedname || sid;
      out.nodes.push({ id: sid, type: fallbackType, label: name });

      // ACE rights: principal --RightName--> this object
      asArray(obj.Aces).forEach(function (ace) {
        const psid = ace && (ace.PrincipalSID || ace.PrincipalID);
        const right = ace && (ace.RightName || ace.Right);
        if (psid && right) out.edges.push({ from: String(psid), to: sid, label: String(right) });
      });

      // Group membership: member --MemberOf--> group
      asArray(obj.Members).forEach(function (m) {
        const msid = m && (m.ObjectIdentifier || m.MemberId);
        if (msid) out.edges.push({ from: String(msid), to: sid, label: 'MemberOf' });
      });

      // Primary group
      const pgsid = props.primarygroupsid || obj.PrimaryGroupSID;
      if (pgsid) out.edges.push({ from: sid, to: String(pgsid), label: 'MemberOf' });

      // Local admins on computers: principal --AdminTo--> computer
      const la = (obj.LocalAdmins && obj.LocalAdmins.Results) || obj.LocalAdmins;
      asArray(la).forEach(function (p) {
        const psid = p && (p.ObjectIdentifier || p.MemberId);
        if (psid) out.edges.push({ from: String(psid), to: sid, label: 'AdminTo' });
      });

      // Sessions on computers: user --HasSession--> computer
      const ses = (obj.Sessions && obj.Sessions.Results) || obj.Sessions;
      asArray(ses).forEach(function (s) {
        const usid = s && s.UserSID;
        if (usid) out.edges.push({ from: String(usid), to: sid, label: 'HasSession' });
      });
    });
    return out;
  }

  /* Build styled vis.js overlay nodes/edges, dropping edges whose endpoints
  * are not part of the imported node set. */
  function ingest(rawNodes, rawEdges) {
    const byId = new Map();
    rawNodes.forEach(function (n) { if (!byId.has(n.id)) byId.set(n.id, n); });

    const nodes = [];
    let nodeOverflow = false;
    byId.forEach(function (n) {
      if (nodes.length >= MAX_NODES) { nodeOverflow = true; return; }
      const style = NODE_STYLE[n.type] || NODE_STYLE.base;
      nodes.push({
        id: 'sh:' + n.id,
        label: shortLabel(n.label),
        title: 'SharpHound import\n' + String(n.type || 'object').toUpperCase() + '\n' + n.label,
        group: 'sharphound',
        sh: true,
        shape: 'diamond',
        size: n.type === 'domain' ? 20 : (n.type === 'group' ? 16 : 13),
        color: { background: '#161b22', border: style.border, highlight: { background: '#21262d', border: '#79c0ff' } },
        borderWidth: 2,
        font: { color: '#8b949e', size: 9, strokeWidth: 2, strokeColor: '#0d1117' }
      });
    });

    const present = new Set();
    nodes.forEach(function (n) { present.add(n.id); });

    const edges = [];
    const seen = new Set();
    let edgeOverflow = false;
    rawEdges.forEach(function (e) {
      if (edges.length >= MAX_EDGES) { edgeOverflow = true; return; }
      const from = 'sh:' + e.from;
      const to = 'sh:' + e.to;
      if (!present.has(from) || !present.has(to)) return;
      const key = from + '|' + to + '|' + e.label;
      if (seen.has(key)) return;
      seen.add(key);
      edges.push({
        id: 'she:' + key,
        from: from,
        to: to,
        label: String(e.label || '').slice(0, 20),
        arrows: 'to',
        dashes: [2, 3],
        color: { color: '#8957e5', highlight: '#bc8cff', opacity: 0.75 },
        width: 1,
        font: { color: '#8b949e', size: 7, strokeWidth: 2, strokeColor: '#0d1117', align: 'top' },
        smooth: { type: 'dynamic' }
      });
    });

    visNodes = nodes;
    visEdges = edges;
    visible = true;
    refreshControls();
    rerender(true);

    emit('SharpHound overlay: ' + nodes.length + ' nodes, ' + edges.length + ' edges merged (graph.json untouched)', 'done');
    if (nodeOverflow || edgeOverflow) {
      emit('SharpHound import truncated to ' + MAX_NODES + ' nodes / ' + MAX_EDGES + ' edges', 'log');
    }
  }

  function refreshControls() {
    const btn = document.getElementById('sh-toggle-btn');
    const legend = document.getElementById('sh-legend');
    const count = document.getElementById('sh-count');
    const has = visNodes.length > 0;
    if (btn) {
      btn.style.display = has ? '' : 'none';
      btn.classList.toggle('sh-on', has && visible);
      const icon = btn.querySelector('i');
      if (icon) icon.className = visible ? 'fa-regular fa-eye' : 'fa-regular fa-eye-slash';
    }
    if (legend) legend.style.display = (has && visible) ? '' : 'none';
    if (count) count.textContent = String(visNodes.length);
  }

  function rerender(fit) {
    if (typeof setGraphFilter === 'function') {
      setGraphFilter(typeof currentGraphFilter !== 'undefined' ? currentGraphFilter : 'all');
    }
    if (fit && typeof network !== 'undefined' && network) {
      try { network.setOptions({ physics: true }); } catch (e) {}
      setTimeout(function () {
        try { network.setOptions({ physics: false }); network.fit({ animation: true }); } catch (e) {}
      }, 1400);
    }
  }

  /* Called from setGraphFilter() — returns overlay layer to merge, or null. */
  function overlayFor(filter) {
    if (!visible || !visNodes.length) return null;
    return { nodes: visNodes, edges: visEdges };
  }

  function toggle() {
    if (!visNodes.length) return;
    visible = !visible;
    refreshControls();
    rerender(false);
    emit('SharpHound overlay ' + (visible ? 'shown' : 'hidden'), 'log');
  }

  /* Recursively walk a JSZip instance, parsing .json and nested .zip files. */
  async function walkZip(zip, acc) {
    const entries = [];
    zip.forEach(function (path, entry) { if (!entry.dir) entries.push(entry); });
    for (const entry of entries) {
      const lower = entry.name.toLowerCase();
      if (lower.endsWith('.json')) {
        try {
          const json = JSON.parse(await entry.async('string'));
          const frag = parseFile(entry.name, json);
          acc.nodes.push.apply(acc.nodes, frag.nodes);
          acc.edges.push.apply(acc.edges, frag.edges);
        } catch (e) {
          emit('Skipped ' + entry.name + ' (parse error)', 'error');
        }
      } else if (lower.endsWith('.zip')) {
        try {
          const inner = await window.JSZip.loadAsync(await entry.async('arraybuffer'));
          await walkZip(inner, acc);
        } catch (e) {
          emit('Skipped nested zip ' + entry.name, 'error');
        }
      }
    }
  }

  async function processZip(file) {
    if (!window.JSZip) { emit('JSZip not loaded — cannot parse SharpHound zip', 'error'); return; }
    emit('Parsing SharpHound archive: ' + file.name, 'phase');
    try {
      const zip = await window.JSZip.loadAsync(file);
      const acc = { nodes: [], edges: [] };
      await walkZip(zip, acc);
      if (!acc.nodes.length) { emit('No BloodHound objects found in ' + file.name, 'error'); return; }
      ingest(acc.nodes, acc.edges);
    } catch (e) {
      emit('Failed to read ' + file.name + ': ' + e, 'error');
    }
  }

  function handleFiles(fileList) {
    const files = Array.prototype.slice.call(fileList || []);
    const zips = files.filter(function (f) { return /\.zip$/i.test(f.name); });
    if (!zips.length) { emit('No .zip file detected', 'error'); return; }
    zips.forEach(processZip);
  }

  function init() {
    const input = document.getElementById('sh-file-input');
    if (input) {
      input.addEventListener('change', function (e) { handleFiles(e.target.files); e.target.value = ''; });
    }
    const area = document.querySelector('.graph-area');
    const dz = document.getElementById('sh-dropzone');
    if (!area) return;
    let depth = 0;
    area.addEventListener('dragenter', function (e) { e.preventDefault(); depth++; if (dz) dz.classList.add('active'); });
    area.addEventListener('dragover', function (e) { e.preventDefault(); if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy'; });
    area.addEventListener('dragleave', function (e) { e.preventDefault(); depth = Math.max(0, depth - 1); if (!depth && dz) dz.classList.remove('active'); });
    area.addEventListener('drop', function (e) {
      e.preventDefault(); depth = 0; if (dz) dz.classList.remove('active');
      if (e.dataTransfer && e.dataTransfer.files) handleFiles(e.dataTransfer.files);
    });
  }

  function collectViaShell() {
    if (typeof opRunning !== 'undefined' && opRunning) {
      var busy = (typeof termRunningLabel !== 'undefined' && termRunningLabel)
        ? termRunningLabel
        : 'another operation';
      emit('Wait — ' + busy + ' is still running (toolkit upload can take several minutes)', 'error');
      return;
    }
    if (typeof runOp !== 'function') {
      emit('Dashboard API unavailable', 'error');
      return;
    }
    var sh = (typeof state !== 'undefined' && state) ? state.shell : null;
    if (!sh || !sh.connected) {
      if (sh && sh.stale_marker) {
        emit('[!] Previous shell ended — run Establish Reverse Shell from this dashboard session first', 'error');
      } else {
        emit('[!] No live reverse shell — run Establish Reverse Shell before SH Collect', 'error');
      }
      if (typeof openPostexModal === 'function') {
        openPostexModal({ lport: (sh && sh.lport) || 443, op: 'postex-006' });
      }
      return;
    }
    runOp('SharpHound collect', '/api/sharphound/collect', { via: 'auto' });
  }

  return { init: init, overlayFor: overlayFor, toggle: toggle, handleFiles: handleFiles, collectViaShell: collectViaShell };
})();

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', SharpHoundImport.init);
} else {
  SharpHoundImport.init();
}
"""
