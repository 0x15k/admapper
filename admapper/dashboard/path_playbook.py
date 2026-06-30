"""Feature 3 — per-hop attack path playbook (presentation-only assets).

When the operator selects a path from ``attack_paths`` (``paths.json`` via
``/api/state``), renders a step-by-step exploitation playbook below the graph.
Commands are resolved from ``admapper.guides.catalog.MANUAL_GUIDE_CATALOG`` at
HTML-build time — the JS never hardcodes technique strings.

Edge metadata comes from ``admapper.graph.catalog.EDGE_CATALOG``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from admapper.graph.catalog import EDGE_CATALOG
from admapper.graph.edge_abuse import edge_abuse_catalog_json, normalize_edge_key
from admapper.guides.catalog import MANUAL_GUIDE_CATALOG

# Edge types that defer to target-type abuse when no explicit command mapping exists.
_TARGET_AWARE_EDGES = frozenset(
    {
        "genericall",
        "genericwrite",
        "allextendedrights",
        "writeowner",
        "owns",
    }
)


def _catalog_cmd(guide_key: str, needle: str, *, fallback: int = 0) -> str:
    guide = MANUAL_GUIDE_CATALOG.get(guide_key)
    if not guide:
        return ""
    for cmd in guide.commands:
        if needle.lower() in cmd.lower():
            return cmd
    if guide.commands:
        idx = min(max(fallback, 0), len(guide.commands) - 1)
        return guide.commands[idx]
    return ""


def _catalog_cmd_any(
    needles: tuple[str, ...],
    *,
    fallback_guide: str = "acl_abuse",
    fallback_needle: str = "acls",
) -> str:
    for guide in MANUAL_GUIDE_CATALOG.values():
        for cmd in guide.commands:
            low = cmd.lower()
            if any(n.lower() in low for n in needles):
                return cmd
    return _catalog_cmd(fallback_guide, fallback_needle, fallback=0)


def _edge_commands() -> dict[str, str]:
    """Map edge_type → command template string (from guides catalog)."""
    explicit: dict[str, Callable[[], str]] = {
      "addmember": lambda: _catalog_cmd_any(("groupMember", "net group", "/add", "addmember")),
      "addself": lambda: _catalog_cmd_any(("addself", "groupMember")),
      "forcechangepassword": lambda: _catalog_cmd_any(
          ("set password", "forcechangepassword", "dacledit")
      ),
      "writedacl": lambda: _catalog_cmd("acl_abuse", "dacledit"),
      "writeowner": lambda: _catalog_cmd("acl_abuse", "dacledit"),
      "writespn": lambda: _catalog_cmd("kerberoast", "GetUserSPNs"),
      "readgmsapassword": lambda: _catalog_cmd("postex_local", "secretsdump"),
      "readlapspassword": lambda: _catalog_cmd("postex_local", "secretsdump"),
      "dcsync": lambda: _catalog_cmd("acl_abuse", "secretsdump"),
      "getchanges": lambda: _catalog_cmd("acl_abuse", "secretsdump"),
      "getchangesall": lambda: _catalog_cmd("acl_abuse", "secretsdump"),
      "shadow_credentials": lambda: _catalog_cmd("kerberos_adv", "pywhisker"),
      "rbcd": lambda: _catalog_cmd("kerberos_adv", "getST"),
      "allowedtoact": lambda: _catalog_cmd("kerberos_adv", "getST"),
      "adminto": lambda: _catalog_cmd("postex_local", "wmiexec"),
      "constrained_delegation": lambda: _catalog_cmd("kerberos_adv", "getST"),
      "constrained_pt": lambda: _catalog_cmd("kerberos_adv", "getST"),
      "unconstrained_delegation": lambda: _catalog_cmd("coercion", "PetitPotam"),
      "member_of": lambda: _catalog_cmd("attack_paths", "paths"),
      "member_of_domain": lambda: _catalog_cmd("start_auth", "bloodhound"),
    }
    return {key: fn() for key, fn in explicit.items() if fn()}


def _target_abuse_commands() -> dict[str, str]:
    """CrownHunter-style EDGE_ABUSE fallback by target node type."""
    return {
        "group": _catalog_cmd_any(("groupMember", "net group", "/add")),
        "user": _catalog_cmd("kerberos_adv", "pywhisker"),
        "computer": _catalog_cmd("kerberos_adv", "getST"),
        "domain": _catalog_cmd("acl_abuse", "secretsdump"),
        "gmsa": _catalog_cmd("postex_local", "secretsdump"),
        "dc": _catalog_cmd("postex_local", "wmiexec"),
    }


def edge_catalog_json() -> str:
    payload = {
        key: {
            "title": entry.title,
            "mitre": entry.mitre_id or "",
            "severity": entry.severity,
            "narrative": entry.narrative,
        }
        for key, entry in EDGE_CATALOG.items()
    }
    return json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")


def playbook_maps_json() -> str:
    """Legacy alias — prefer EDGE_ABUSE_CATALOG in new code."""
    return edge_abuse_catalog_json()


def edge_abuse_maps_json() -> str:
    return edge_abuse_catalog_json()


PATHS_PANEL = """
<div class="panel" style="border-left:3px solid var(--yellow);">
  <div class="panel-header">Attack Paths <span class="panel-count" id="paths-count">0</span></div>
  <div id="paths-list" style="max-height:170px;overflow-y:auto;padding-right:2px;">
    <div class="nd-empty">No attack paths computed — run paths after auth</div>
  </div>
</div>
"""

PATH_PLAYBOOK_PANEL = """
<div id="path-playbook-panel" class="path-playbook-panel">
  <div class="pb-header">
    <div>
      <div class="pb-title" id="pb-title">Path playbook</div>
      <div class="pb-meta" id="pb-meta"></div>
    </div>
    <div class="pb-actions">
      <button class="btn-graph-ctl" onclick="PathPlaybook.copyMarkdown()" title="Copy full chain as Markdown">
        <i class="fa-regular fa-copy"></i> Copy all
      </button>
      <button class="btn-graph-ctl" onclick="PathPlaybook.close()" title="Close playbook panel">
        <i class="fa-solid fa-xmark"></i>
      </button>
    </div>
  </div>
  <div id="path-playbook-steps" class="pb-steps"></div>
</div>
"""

PATH_PLAYBOOK_CSS = """
/* ── Attack path playbook (Feature 3) ────────────────────── */
.path-item{
  background:var(--bg-card);border:1px solid var(--border);border-radius:4px;
  padding:0.45rem 0.55rem;margin-bottom:0.3rem;cursor:pointer;transition:border-color 0.15s;
}
.path-item:hover{border-color:var(--border-light)}
.path-item.sel{border-color:var(--orange);box-shadow:0 0 0 1px rgba(240,136,62,0.35)}
.path-item .pi-head{display:flex;justify-content:space-between;gap:0.35rem;align-items:baseline}
.path-item .pi-id{font-family:var(--mono);font-size:0.62rem;color:var(--text-muted)}
.path-item .pi-route{font-size:0.72rem;font-weight:600;color:var(--text)}
.path-item .pi-meta{font-size:0.6rem;color:var(--text-dim);margin-top:0.15rem}
.path-playbook-panel{
  position:absolute;left:0;right:0;bottom:0;z-index:7;display:none;
  max-height:42%;overflow:hidden;
  background:rgba(22,27,34,0.97);border-top:1px solid var(--border);
  backdrop-filter:blur(4px);flex-direction:column;
}
.path-playbook-panel.open{display:flex}
.pb-header{
  display:flex;justify-content:space-between;align-items:flex-start;gap:0.5rem;
  padding:0.5rem 0.75rem;border-bottom:1px solid var(--border);flex-shrink:0;
}
.pb-title{font-size:0.78rem;font-weight:700;color:var(--accent-glow)}
.pb-meta{font-size:0.62rem;color:var(--text-dim);margin-top:0.15rem}
.pb-actions{display:flex;gap:0.3rem;flex-shrink:0}
.pb-steps{overflow-y:auto;padding:0.5rem 0.75rem 0.65rem;flex:1}
.pb-step{
  border:1px solid var(--border);border-radius:5px;padding:0.45rem 0.55rem;
  margin-bottom:0.35rem;background:var(--bg-card);
}
.pb-step .ps-hdr{display:flex;justify-content:space-between;gap:0.35rem;margin-bottom:0.25rem}
.pb-step .ps-num{font-size:0.58rem;font-weight:700;color:var(--orange);text-transform:uppercase}
.pb-step .ps-edge{font-size:0.68rem;font-weight:600;color:var(--text)}
.pb-step .ps-mitre{font-size:0.58rem;color:var(--text-muted);font-family:var(--mono)}
.pb-step .ps-detail{font-size:0.65rem;color:var(--text-dim);margin-bottom:0.3rem;line-height:1.35}
.pb-step .ps-cmd{
  background:#0d1117;border:1px solid var(--border);border-radius:4px;
  padding:0.35rem 0.45rem;font-family:var(--mono);font-size:0.66rem;
  display:flex;justify-content:space-between;align-items:flex-start;gap:0.35rem;
  cursor:pointer;
}
.pb-step .ps-cmd:hover{border-color:var(--border-light)}
.pb-step .ps-cmd code{flex:1;white-space:pre-wrap;word-break:break-all;color:var(--text)}
"""

PATH_PLAYBOOK_JS = r"""
/* ── Per-hop path playbook (Feature 3) ───────────────────── */
const PathPlaybook = (function () {
  let paths = [];
  let graphNodeIndex = {};
  let selectedId = null;
  let lastMarkdown = '';

  function escH(s) {
    const d = document.createElement('div');
    d.textContent = String(s == null ? '' : s);
    return d.innerHTML;
  }

  function fmtCmd(cmd) {
    return escH(cmd).replace(/&lt;([A-Za-z0-9_]+)&gt;/g, '<span class="cmd-ph">&lt;$1&gt;</span>');
  }

  function substitute(cmd, extra) {
    if (typeof CommandCheatsheet !== 'undefined' && CommandCheatsheet.substitute) {
      return CommandCheatsheet.substitute(cmd, extra || {});
    }
    return cmd;
  }

  function labelFor(nodeId) {
    const n = graphNodeIndex[nodeId];
    if (!n) return nodeId || '?';
    return n.label || n.username || nodeId;
  }

  function typeFor(nodeId) {
    const n = graphNodeIndex[nodeId];
    if (!n) {
      const low = String(nodeId || '').toLowerCase();
      if (low.startsWith('group:')) return 'group';
      if (low.startsWith('computer:') || low.startsWith('dc:')) return 'computer';
      if (low.startsWith('user:') || low.startsWith('gmsa:')) return 'user';
      if (low.startsWith('domain:')) return 'domain';
      return 'unknown';
    }
    const g = String(n.group || '').toLowerCase();
    if (g === 'group') return 'group';
    if (g === 'computer' || g === 'dc') return 'computer';
    if (g === 'domain') return 'domain';
    if (g === 'gmsa') return 'gmsa';
    if (g === 'user' || g === 'operator' || g === 'highvalue') return 'user';
    return g || 'unknown';
  }

  function edgeMeta(edgeType) {
    const cat = (typeof EDGE_CATALOG_JS !== 'undefined') ? EDGE_CATALOG_JS : {};
    const key = String(edgeType || '').toLowerCase().replace(/\s+/g, '_');
    return cat[key] || { title: edgeType, mitre: '', severity: 'info', narrative: '' };
  }

  function resolveCommand(edgeType, targetType) {
    const catalog = (typeof EDGE_ABUSE_CATALOG !== 'undefined') ? EDGE_ABUSE_CATALOG : {};
    const et = String(edgeType || '').toLowerCase().replace(/\s+/g, '_');
    const norm = et.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
    const keys = [et, norm, et.replace(/_/g, ''), norm.replace(/_/g, '')];
    let entry = null;
    for (let i = 0; i < keys.length; i++) {
      if (catalog[keys[i]]) { entry = catalog[keys[i]]; break; }
    }
    if (!entry) {
      const maps = (typeof PLAYBOOK_MAPS !== 'undefined') ? PLAYBOOK_MAPS : { by_edge: {}, by_target: {} };
      const legacy = maps.by_edge && maps.by_edge[et];
      if (legacy) return legacy;
      const fb = maps.by_target && maps.by_target[targetType];
      return fb || 'ADMapper acls -w <workspace>';
    }
    const tgt = String(targetType || '').toLowerCase();
    if (entry.target_aware && entry.by_target && entry.by_target[tgt] && entry.by_target[tgt].command) {
      return entry.by_target[tgt].command;
    }
    return entry.default_command || '';
  }

  function buildStep(step, idx, path) {
    const edgeType = step.edge_type || step.relation || 'edge';
    const meta = edgeMeta(edgeType);
    const tgtId = step.target || '';
    const srcId = step.source || '';
    const tgtType = typeFor(tgtId);
    const srcLabel = labelFor(srcId);
    const tgtLabel = labelFor(tgtId);
    const narrative = step.narrative || meta.narrative
      .replace('{source}', srcLabel)
      .replace('{target}', tgtLabel)
      .replace('{edge_type}', edgeType)
      .replace('{targets}', tgtLabel);
  const rawCmd = resolveCommand(edgeType, tgtType);
    const cmd = substitute(rawCmd, {
      user: tgtLabel.replace(/^\★\s*/, '').split('@')[0],
      target: tgtLabel,
      spn: 'cifs/' + tgtLabel.split('.')[0]
    });
    return {
      hop: idx + 1,
      edgeType: edgeType,
      technique: meta.title || edgeType,
      mitre: step.mitre_id || meta.mitre || '',
      targetType: tgtType,
      narrative: narrative,
      command: cmd,
      rawCommand: rawCmd
    };
  }

  function highlightPathOnGraph(path) {
    if (!path || typeof setGraphFilter !== 'function') return;
    currentGraphFilter = 'path';
    if (typeof graphEdges !== 'undefined' && path.steps) {
      const stepKeys = new Set();
      path.steps.forEach(function (st) {
        stepKeys.add(String(st.source) + '|' + String(st.target) + '|' + String(st.edge_type || '').toLowerCase().replace(/\s+/g, ''));
      });
      graphEdges.forEach(function (e) {
        const et = String(e.label || '').toLowerCase().replace(/\s+/g, '');
        if (stepKeys.has(String(e.from) + '|' + String(e.to) + '|' + et)) {
          e.path_id = path.id;
          e.pivot_edge = true;
        }
      });
    }
    setGraphFilter('path');
  }

  function renderSteps(path) {
    const panel = document.getElementById('path-playbook-panel');
    const stepsEl = document.getElementById('path-playbook-steps');
    const titleEl = document.getElementById('pb-title');
    const metaEl = document.getElementById('pb-meta');
    if (!panel || !stepsEl) return;

    const steps = (path.steps || []).map(function (st, i) { return buildStep(st, i, path); });
    titleEl.textContent = (path.id || 'path') + ' — exploitation playbook';
    metaEl.textContent = (path.source_label || labelFor(path.source)) + ' → ' +
      (path.target_label || labelFor(path.target)) + ' · ' + steps.length + ' hop(s) · impact ' + (path.impact || '?');

    let md = '# Attack path ' + (path.id || '') + '\n\n';
    md += '**Route:** ' + (path.source_label || '') + ' → ' + (path.target_label || '') + '\n\n';

    let html = '';
    steps.forEach(function (s) {
      md += '## Hop ' + s.hop + ': ' + s.technique + '\n';
      md += '- **Edge:** `' + s.edgeType + '`\n';
      md += '- **Target type:** `' + s.targetType + '`\n';
      if (s.mitre) md += '- **MITRE:** `' + s.mitre + '`\n';
      md += '- ' + s.narrative + '\n';
      md += '```\n' + s.command + '\n```\n\n';

      html += '<div class="pb-step">' +
        '<div class="ps-hdr"><span class="ps-num">Hop ' + s.hop + '</span>' +
        '<span class="ps-edge">' + escH(s.technique) + ' <span style="color:var(--text-muted);font-weight:400">(' + escH(s.edgeType) + ')</span></span>' +
        (s.mitre ? '<span class="ps-mitre">' + escH(s.mitre) + '</span>' : '') +
        '</div>' +
        '<div class="ps-detail">' + escH(s.narrative) + ' · target <strong>' + escH(s.targetType) + '</strong></div>' +
        '<div class="ps-cmd" data-copy-val="' + escH(s.command) + '" data-copy-label="Playbook command" title="Click to copy">' +
        '<code>' + fmtCmd(s.command) + '</code><i class="fa-regular fa-copy copy-icon"></i></div>' +
        '</div>';
    });
    lastMarkdown = md;
    stepsEl.innerHTML = html || '<div class="nd-empty">Path has no steps</div>';
    panel.classList.add('open');
    highlightPathOnGraph(path);
  }

  function selectPath(pathId) {
    selectedId = pathId;
    document.querySelectorAll('.path-item').forEach(function (el) {
      el.classList.toggle('sel', el.dataset.pathId === pathId);
    });
    const path = paths.find(function (p) { return String(p.id) === String(pathId); });
    if (path) renderSteps(path);
  }

  function renderPathList() {
    const el = document.getElementById('paths-list');
    const countEl = document.getElementById('paths-count');
    if (!el) return;
    el.innerHTML = '';
    if (countEl) countEl.textContent = String(paths.length);
    if (!paths.length) {
      el.innerHTML = '<div class="nd-empty">No attack paths computed — run paths after auth</div>';
      return;
    }
    paths.forEach(function (p) {
      const row = document.createElement('div');
      row.className = 'path-item' + (String(p.id) === String(selectedId) ? ' sel' : '');
      row.dataset.pathId = p.id || '';
      row.onclick = function () { selectPath(p.id); };
      const hops = (p.steps || []).length || p.length || 0;
      row.innerHTML =
        '<div class="pi-head">' +
          '<span class="pi-route">' + escH(p.source_label || labelFor(p.source)) + ' → ' + escH(p.target_label || labelFor(p.target)) + '</span>' +
          '<span class="pi-id">' + escH(p.id || '') + '</span>' +
        '</div>' +
        '<div class="pi-meta">' + hops + ' hop(s) · impact ' + escH(p.impact || '?') + '</div>';
      el.appendChild(row);
    });
  }

  function syncFromState(s) {
    if (!s) return;
    paths = s.attack_paths || [];
    graphNodeIndex = {};
    const nodes = (s.graph && s.graph.nodes) ? s.graph.nodes : [];
    nodes.forEach(function (n) { if (n && n.id) graphNodeIndex[n.id] = n; });
    if (typeof graphNodes !== 'undefined') {
      graphNodes.forEach(function (n) { if (n && n.id) graphNodeIndex[n.id] = n; });
    }
    renderPathList();
    if (selectedId) {
      const still = paths.find(function (p) { return String(p.id) === String(selectedId); });
      if (still) renderSteps(still);
      else { selectedId = null; close(); }
    }
  }

  function close() {
    const panel = document.getElementById('path-playbook-panel');
    if (panel) panel.classList.remove('open');
    selectedId = null;
    document.querySelectorAll('.path-item').forEach(function (el) { el.classList.remove('sel'); });
  }

  function copyMarkdown() {
    if (!lastMarkdown) return;
    if (typeof copyToClipboard === 'function') copyToClipboard(lastMarkdown, 'Playbook Markdown');
  }

  return { syncFromState: syncFromState, selectPath: selectPath, close: close, copyMarkdown: copyMarkdown };
})();
"""
