"""BloodHound overlay — server-side JSON merge + dashboard presentation assets.

Parses bloodhound-python / BloodHound CE JSON files from ``bloodhound/`` and
writes ``bloodhound_overlay.json`` (vis.js-ready nodes/edges with ``bh:`` prefix).
The SPA merges this layer in ``setGraphFilter()`` alongside the client-side
SharpHound ZIP overlay (``sh:`` prefix).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

OVERLAY_FILENAME = "bloodhound_overlay.json"
MAX_NODES = 2000
MAX_EDGES = 4000

NODE_BORDER = {
    "user": "#58a6ff",
    "computer": "#79c0ff",
    "group": "#f0a35e",
    "domain": "#f85149",
    "gpo": "#56d4dd",
    "ou": "#8b949e",
    "container": "#8b949e",
    "base": "#388bfd",
}

SKIP_JSON = frozenset({OVERLAY_FILENAME, "collection_manifest.json"})


def _type_from_name(name: str) -> str:
    n = name.lower()
    if "computers" in n:
        return "computer"
    if "users" in n:
        return "user"
    if "groups" in n:
        return "group"
    if "domains" in n:
        return "domain"
    if "gpos" in n:
        return "gpo"
    if "ous" in n:
        return "ou"
    if "containers" in n:
        return "container"
    return "base"


def _as_array(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def parse_bloodhound_json_file(
    file_name: str, payload: dict[str, Any]
) -> tuple[list[dict], list[dict]]:
    """Parse one BloodHound JSON file into raw {id, type, label} nodes and edges."""
    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []

    meta_type = ""
    meta = payload.get("meta")
    if isinstance(meta, dict):
        meta_type = str(meta.get("type") or "")
    fallback_type = _type_from_name(meta_type or file_name)
    items = payload.get("data") if isinstance(payload.get("data"), list) else []

    for obj in items:
        if not isinstance(obj, dict):
            continue
        props = obj.get("Properties") if isinstance(obj.get("Properties"), dict) else {}
        obj_id = obj.get("ObjectIdentifier") or obj.get("ObjectID") or props.get("objectid")
        if not obj_id:
            continue
        sid = str(obj_id)
        name = str(props.get("name") or props.get("distinguishedname") or sid)
        nodes.append({"id": sid, "type": fallback_type, "label": name})

        for ace in _as_array(obj.get("Aces")):
            if not isinstance(ace, dict):
                continue
            principal = ace.get("PrincipalSID") or ace.get("PrincipalID")
            right = ace.get("RightName") or ace.get("Right")
            if principal and right:
                edges.append(
                    {"from": str(principal), "to": sid, "label": str(right)},
                )

        for member in _as_array(obj.get("Members")):
            if not isinstance(member, dict):
                continue
            member_id = member.get("ObjectIdentifier") or member.get("MemberId")
            if member_id:
                edges.append({"from": str(member_id), "to": sid, "label": "MemberOf"})

        primary = props.get("primarygroupsid") or obj.get("PrimaryGroupSID")
        if primary:
            edges.append({"from": sid, "to": str(primary), "label": "MemberOf"})

        local_admins = obj.get("LocalAdmins")
        if isinstance(local_admins, dict):
            local_admins = local_admins.get("Results")
        for principal in _as_array(local_admins):
            if not isinstance(principal, dict):
                continue
            principal_id = principal.get("ObjectIdentifier") or principal.get("MemberId")
            if principal_id:
                edges.append(
                    {"from": str(principal_id), "to": sid, "label": "AdminTo"},
                )

        sessions = obj.get("Sessions")
        if isinstance(sessions, dict):
            sessions = sessions.get("Results")
        for session in _as_array(sessions):
            if not isinstance(session, dict):
                continue
            user_sid = session.get("UserSID")
            if user_sid:
                edges.append({"from": str(user_sid), "to": sid, "label": "HasSession"})

    return nodes, edges


def _short_label(text: str, limit: int = 22) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 2] + "..."


def build_vis_overlay(
    raw_nodes: list[dict[str, str]],
    raw_edges: list[dict[str, str]],
    *,
    max_nodes: int = MAX_NODES,
    max_edges: int = MAX_EDGES,
    domain: str | None = None,
    source: str = "bloodhound-python",
) -> dict[str, Any]:
    """Convert raw BloodHound objects into vis.js overlay nodes/edges (``bh:`` prefix)."""
    if not raw_edges and raw_nodes and domain:
        domain_lc = domain.strip().lower()
        hub_id = f"bh-domain:{domain_lc}"
        if not any(n.get("id") == hub_id for n in raw_nodes):
            raw_nodes = [
                *raw_nodes,
                {"id": hub_id, "type": "domain", "label": domain_lc},
            ]
        for node in raw_nodes:
            if node.get("id") == hub_id:
                continue
            raw_edges.append(
                {"from": str(node["id"]), "to": hub_id, "label": "in domain"},
            )
    by_id: dict[str, dict[str, str]] = {}
    for node in raw_nodes:
        nid = node.get("id")
        if nid and nid not in by_id:
            by_id[str(nid)] = node

    vis_nodes: list[dict[str, Any]] = []
    node_overflow = False
    for node in by_id.values():
        if len(vis_nodes) >= max_nodes:
            node_overflow = True
            break
        ntype = str(node.get("type") or "base")
        border = NODE_BORDER.get(ntype, NODE_BORDER["base"])
        label = _short_label(str(node.get("label") or node.get("id") or ""))
        vis_nodes.append(
            {
                "id": f"bh:{node['id']}",
                "label": label,
                "title": f"BloodHound collect\n{ntype.upper()}\n{node.get('label', '')}",
                "group": "bloodhound",
                "bh": True,
                "shape": "diamond",
                "size": 20 if ntype == "domain" else (16 if ntype == "group" else 13),
                "color": {
                    "background": "#161b22",
                    "border": border,
                    "highlight": {"background": "#21262d", "border": "#79c0ff"},
                },
                "borderWidth": 2,
                "font": {
                    "color": "#8b949e",
                    "size": 0 if ntype != "domain" else 9,
                    "strokeWidth": 2,
                    "strokeColor": "#0d1117",
                },
            }
        )

    present = {n["id"] for n in vis_nodes}
    vis_edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    edge_overflow = False

    for edge in raw_edges:
        if len(vis_edges) >= max_edges:
            edge_overflow = True
            break
        from_id = f"bh:{edge['from']}"
        to_id = f"bh:{edge['to']}"
        if from_id not in present or to_id not in present:
            continue
        label = str(edge.get("label") or "edge")
        key = f"{from_id}|{to_id}|{label}"
        if key in seen:
            continue
        seen.add(key)
        vis_edges.append(
            {
                "id": f"bhe:{key}",
                "from": from_id,
                "to": to_id,
                "label": label[:20],
                "arrows": "to",
                "dashes": [4, 4],
                "color": {"color": "#388bfd", "highlight": "#58a6ff", "opacity": 0.8},
                "width": 1,
                "font": {
                    "color": "#8b949e",
                    "size": 7,
                    "strokeWidth": 2,
                    "strokeColor": "#0d1117",
                    "align": "top",
                },
                "smooth": {"type": "dynamic"},
            }
        )

    return {
        "nodes": vis_nodes,
        "edges": vis_edges,
        "meta": {
            "node_count": len(vis_nodes),
            "edge_count": len(vis_edges),
            "truncated": node_overflow or edge_overflow,
            "source": source,
        },
    }


def parse_bloodhound_directory(bh_dir: Path) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Load and merge all BloodHound JSON files under ``bloodhound/``."""
    raw_nodes: list[dict[str, str]] = []
    raw_edges: list[dict[str, str]] = []
    if not bh_dir.is_dir():
        return raw_nodes, raw_edges

    for path in sorted(bh_dir.glob("*.json")):
        if path.name in SKIP_JSON:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        nodes, edges = parse_bloodhound_json_file(path.name, payload)
        raw_nodes.extend(nodes)
        raw_edges.extend(edges)

    return raw_nodes, raw_edges


def build_and_save_overlay(ws_path: Path, *, domain: str | None = None) -> Path | None:
    """Parse ``bloodhound/*.json`` and write ``bloodhound_overlay.json``."""
    bh_dir = ws_path / "bloodhound"
    raw_nodes, raw_edges = parse_bloodhound_directory(bh_dir)
    if not raw_nodes:
        overlay_path = ws_path / OVERLAY_FILENAME
        if overlay_path.is_file():
            overlay_path.unlink()
        return None

    if not domain:
        state_path = ws_path / "state.json"
        if state_path.is_file():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
                domain = str(state.get("domain") or "") or None
            except (OSError, json.JSONDecodeError):
                domain = None

    overlay = build_vis_overlay(
        raw_nodes,
        raw_edges,
        domain=domain,
        source="sharphound" if any(bh_dir.glob("sh_*.json")) else "bloodhound-python",
    )
    overlay["meta"]["updated_at"] = datetime.now(UTC).isoformat()
    if domain:
        overlay["meta"]["domain"] = domain

    out_path = ws_path / OVERLAY_FILENAME
    out_path.write_text(json.dumps(overlay, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out_path


def load_overlay_for_payload(ws_path: Path) -> dict[str, Any] | None:
    """Return overlay dict for ``build_ops_payload()`` graph enrichment."""
    path = ws_path / OVERLAY_FILENAME
    if not path.is_file():
        bh_dir = ws_path / "bloodhound"
        if bh_dir.is_dir() and any(bh_dir.glob("*.json")):
            build_and_save_overlay(ws_path)
            if not path.is_file():
                return None
        else:
            return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if not data.get("nodes"):
        return None
    return data


# ── Dashboard presentation (graph controls + overlay JS) ───────────────────

BLOODHOUND_COLLECT_CONTROLS = """
<button class="btn-graph-ctl" id="bh-collect-btn" onclick="BloodHoundOverlay.collect()" title="Run bloodhound-python with workspace credentials (writes to bloodhound/)"><i class="fa-solid fa-play"></i> BH Collect</button>
<button class="btn-graph-ctl" id="bh-toggle-btn" onclick="BloodHoundOverlay.toggle()" style="display:none" title="Toggle server-side BloodHound overlay layer"><i class="fa-regular fa-eye"></i> BH Layer <span id="bh-count">0</span></button>
"""

BLOODHOUND_LEGEND = (
    '<div class="legend-item" id="bh-legend" style="display:none;color:#58a6ff">'
    '<i class="fa-solid fa-gem"></i> BloodHound (collected)</div>'
)

BLOODHOUND_OVERLAY_CSS = """
.btn-graph-ctl.bh-on{background:#388bfd;border-color:#388bfd;color:#0d1117}
#bh-count{
  background:rgba(0,0,0,0.25);border-radius:6px;padding:0 0.25rem;
  font-size:0.6rem;margin-left:0.1rem;
}
"""

BLOODHOUND_OVERLAY_JS = r"""
/* ── Server-side BloodHound overlay (bloodhound-python) ───── */
const BloodHoundOverlay = (function () {
  let visNodes = [];
  let visEdges = [];
  let visible = true;

  function emit(text, kind) {
    if (typeof termLogSemantic === 'function') termLogSemantic(text, kind || 'log');
  }

  function refreshControls() {
    const btn = document.getElementById('bh-toggle-btn');
    const legend = document.getElementById('bh-legend');
    const count = document.getElementById('bh-count');
    const has = visNodes.length > 0;
    if (btn) {
      btn.style.display = has ? '' : 'none';
      btn.classList.toggle('bh-on', has && visible);
      const icon = btn.querySelector('i');
      if (icon) icon.className = visible ? 'fa-regular fa-eye' : 'fa-regular fa-eye-slash';
    }
    if (legend) legend.style.display = (has && visible) ? '' : 'none';
    if (count) count.textContent = String(visNodes.length);
  }

  function rerender() {
    if (typeof setGraphFilter === 'function') {
      setGraphFilter(typeof currentGraphFilter !== 'undefined' ? currentGraphFilter : 'all');
    }
  }

  function ingest(overlay) {
    if (!overlay) {
      visNodes = [];
      visEdges = [];
      refreshControls();
      rerender();
      return;
    }
    visNodes = Array.isArray(overlay.nodes) ? overlay.nodes.slice() : [];
    visEdges = Array.isArray(overlay.edges) ? overlay.edges.slice() : [];
    visible = visNodes.length <= 28;
    refreshControls();
    rerender();
    const meta = overlay.meta || {};
    emit('BloodHound overlay: ' + (meta.node_count || visNodes.length) + ' nodes, ' +
      (meta.edge_count || visEdges.length) + ' edges (graph.json untouched)', 'done');
  }

  function syncFromState(s) {
    if (!s || !s.graph) return;
    const ov = s.graph.bloodhound_overlay;
    if (!ov || !ov.nodes || !ov.nodes.length) {
      if (visNodes.length) ingest(null);
      return;
    }
    const sameCount = visNodes.length === ov.nodes.length;
    if (!sameCount || visNodes[0]?.id !== ov.nodes[0]?.id) ingest(ov);
    else refreshControls();
  }

  function overlayFor(filter) {
    if (!visible || !visNodes.length) return null;
    return { nodes: visNodes, edges: visEdges };
  }

  function toggle() {
    if (!visNodes.length) return;
    visible = !visible;
    refreshControls();
    rerender();
    emit('BloodHound overlay ' + (visible ? 'shown' : 'hidden'), 'log');
  }

  function collect() {
    if (typeof opRunning !== 'undefined' && opRunning) {
      emit('Another operation is already running', 'error');
      return;
    }
    if (typeof apiPost !== 'function') {
      emit('Dashboard API unavailable', 'error');
      return;
    }
    emit('Starting bloodhound-python collection…', 'phase');
    apiPost('/api/bloodhound', { collect: 'All' });
  }

  return { syncFromState: syncFromState, overlayFor: overlayFor, toggle: toggle, collect: collect, ingest: ingest };
})();
"""
