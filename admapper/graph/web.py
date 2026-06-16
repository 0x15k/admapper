from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from admapper.escalate.edges import collect_edges_from_pivot, pick_next_edge
from admapper.creds.common import collect_gained_hashes, format_evil_winrm_pth
from admapper.report.engagement import _load_json
from admapper.report.engagement_map import _acl_exploit_blocker, loot_clue_rows


def _esc(text: str) -> str:
    return html.escape(str(text or ""))


def _node_color(node: dict[str, Any], *, pivot: str, owned: set[str]) -> str:
    username = str(node.get("username", "")).lower()
    name = str(node.get("name", "")).lower()
    if node.get("owned") or username in owned:
        return "#22c55e"
    if username == pivot.lower() or name == pivot.lower():
        return "#f97316"
    if node.get("high_value"):
        return "#ef4444"
    ntype = str(node.get("type", ""))
    if ntype == "computer":
        return "#6366f1"
    if ntype == "group":
        return "#8b5cf6"
    if ntype == "gmsa" or "msa_" in username:
        return "#06b6d4"
    return "#64748b"


def build_graph_payload(
    ws_path: Path,
    *,
    domain: str,
    pivot_user: str | None = None,
    owned_users: list[str] | None = None,
) -> dict[str, Any]:
    """Collect nodes/edges for vis-network from graph.json + ACLs + escalate."""
    owned = {u.lower() for u in (owned_users or [])}
    pivot = pivot_user or (list(owned_users or [])[-1] if owned_users else "")
    graph = _load_json(ws_path / "graph.json") or {"nodes": [], "edges": []}
    acl = _load_json(ws_path / "acl_findings.json") or {}

    vis_nodes: dict[str, dict] = {}
    vis_edges: list[dict] = []

    def add_node(
        nid: str,
        label: str,
        group: str,
        color: str,
        title: str = "",
        *,
        username: str = "",
        identity_role: str = "unknown",
    ) -> None:
        if nid in vis_nodes:
            existing = vis_nodes[nid]
            if username:
                existing["username"] = username
            if identity_role != "unknown":
                existing["identity_role"] = identity_role
            return
        vis_nodes[nid] = {
            "id": nid,
            "label": label,
            "group": group,
            "color": color,
            "title": title or label,
            "font": {"color": "#f8fafc" if color != "#64748b" else "#0f172a"},
            "username": username,
            "identity_role": identity_role,
        }

    for node in graph.get("nodes", []):
        nid = str(node.get("id", ""))
        if not nid:
            continue
        username = str(node.get("username") or node.get("name") or nid.split(":")[0])
        label = username
        is_owned = bool(node.get("owned")) or username.lower() in owned
        if is_owned:
            label = f"★ {label}"
        role = "unknown"
        ul = username.lower()
        if ul == pivot.lower():
            role = "pivot"
        elif is_owned:
            role = "owned"
        add_node(
            nid,
            label,
            str(node.get("type", "object")),
            _node_color(node, pivot=pivot, owned=owned),
            title=json.dumps(node, indent=2),
            username=username,
            identity_role=role,
        )

    for edge in graph.get("edges", []):
        src = str(edge.get("source", ""))
        tgt = str(edge.get("target", ""))
        if not src or not tgt:
            continue
        etype = str(edge.get("type", edge.get("right", "edge")))
        from_pivot = pivot and src == f"user:{pivot.lower()}@{domain.lower()}"
        vis_edges.append(
            {
                "id": f"e:{src}:{tgt}:{etype}",
                "from": src,
                "to": tgt,
                "label": etype.replace("_", " ")[:24],
                "arrows": "to",
                "color": {"color": "#3dffcf" if from_pivot else "#94a3b8"},
                "width": 3 if from_pivot else 2,
                "pivot_edge": from_pivot,
            }
        )

    for finding in acl.get("findings") or []:
        principal = str(finding.get("principal", ""))
        target = str(finding.get("target_name", ""))
        right = str(finding.get("right", "acl"))
        if not principal or not target:
            continue
        p_id = f"user:{principal.lower()}@{domain.lower()}"
        t_id = f"gmsa:{target.lower()}@{domain.lower()}"
        add_node(
            p_id,
            principal,
            "user",
            _node_color({"username": principal, "owned": principal.lower() in owned}, pivot=pivot, owned=owned),
            username=principal,
            identity_role="pivot" if principal.lower() == pivot.lower() else (
                "owned" if principal.lower() in owned else "unknown"
            ),
        )
        add_node(t_id, target, "gmsa", "#06b6d4", title=finding.get("detail", ""))
        vis_edges.append(
            {
                "id": f"e:{p_id}:{t_id}:{right}",
                "from": p_id,
                "to": t_id,
                "label": right,
                "arrows": "to",
                "color": {"color": "#f59e0b"},
                "width": 3,
                "dashes": False,
            }
        )

    next_edge = None
    next_hop_detail: str | None = None
    next_hop_cmd: str | None = None
    if pivot:
        edges = collect_edges_from_pivot(
            pivot_user=pivot,
            owned_users=list(owned_users or []),
            ws_path=ws_path,
            domain=domain,
        )
        next_edge = pick_next_edge(edges)

    hashes = collect_gained_hashes(ws_path)
    gained_hashes = [{"account": a, "nthash": h} for a, h in hashes]
    if hashes:
        account, nthash = hashes[-1]
        host, winrm_cmd = format_evil_winrm_pth(
            account=account,
            nthash=nthash,
            domain=domain,
            ws_path=ws_path,
        )
        next_hop_detail = f"{account} ──WinRM──► {host} (postex)"
        next_hop_cmd = winrm_cmd
    elif next_edge:
        next_hop_detail = (
            f"{pivot} ──{next_edge.technique}──► {next_edge.target or '?'}"
            if pivot
            else next_edge.title
        )

    acl_blocker = _acl_exploit_blocker(ws_path)

    result: dict[str, Any] = {
        "nodes": list(vis_nodes.values()),
        "edges": vis_edges,
        "pivot": pivot,
        "owned": list(owned_users or []),
        "next_hop": next_hop_detail or (next_edge.title if next_edge else None),
        "next_hop_cmd": next_hop_cmd,
        "gained_hashes": gained_hashes,
        "acl_blocker": acl_blocker,
        "hidden_nodes": 0,
    }
    return result


def build_attack_graph_html(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
) -> str:
    domain_s = domain or "(sin dominio)"
    payload = build_graph_payload(
        ws_path,
        domain=domain_s,
        pivot_user=pivot_user,
        owned_users=owned_users,
    )
    intel = _load_json(ws_path / "user_intel.json") or {}
    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    dc_ip = ""
    for host in unauth.get("hosts") or []:
        if host.get("is_domain_controller"):
            dc_ip = str(host.get("address", ""))
            break

    user_rows = ""
    for u in intel.get("users") or []:
        src = ", ".join(u.get("sources") or [])
        user_rows += (
            f"<tr><td>{_esc(u.get('username'))}</td>"
            f"<td>{'✓' if u.get('in_domain') else 'loot'}</td>"
            f"<td>{_esc(u.get('cred_status') or '-')}</td>"
            f"<td><code>{_esc(src)}</code></td></tr>"
        )

    clue_rows = ""
    for clue in loot_clue_rows(ws_path):
        clue_rows += (
            f"<tr><td>{_esc(clue['user'])}</td>"
            f"<td><code>{_esc(clue['string'])}</code></td>"
            f"<td>{_esc(clue['verify_state'])}</td>"
            f"<td><code>{_esc(clue['source'])}</code></td></tr>"
        )

    graph_json = json.dumps(payload)

    hash_rows = ""
    for item in payload.get("gained_hashes") or []:
        account = str(item.get("account", ""))
        nthash = str(item.get("nthash", ""))
        if not account or not nthash:
            continue
        _, winrm_cmd = format_evil_winrm_pth(
            account=account,
            nthash=nthash,
            domain=domain_s,
            ws_path=ws_path,
            fallback_ip=dc_ip or None,
        )
        hash_rows += (
            f"<tr><td><code>{_esc(account)}</code></td>"
            f"<td><code>{_esc(nthash)}</code></td>"
            f"<td><code>{_esc(winrm_cmd)}</code></td></tr>"
        )

    next_hop_block = ""
    if payload.get("next_hop"):
        cmd_line = ""
        if payload.get("next_hop_cmd"):
            cmd_line = f"<br/><code>{_esc(payload['next_hop_cmd'])}</code>"
        next_hop_block = (
            "<div class='next'><strong>Siguiente paso</strong><br/>"
            + _esc(payload.get("next_hop") or "")
            + cmd_line
            + "</div>"
        )

    blocker_block = ""
    if payload.get("acl_blocker"):
        blocker_block = (
            "<div class='blocker'><strong>⚠ Bloqueo</strong><br/>"
            f"<code>{_esc(payload['acl_blocker'])}</code></div>"
        )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>ADMapper Graph — {_esc(workspace)}</title>
  <script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; }}
    header {{ padding: 1rem 1.5rem; background: #1e293b; border-bottom: 1px solid #334155; }}
    h1 {{ margin: 0; font-size: 1.25rem; color: #38bdf8; }}
    .meta {{ color: #94a3b8; font-size: 0.9rem; margin-top: 0.35rem; }}
    .layout {{ display: grid; grid-template-columns: 340px 1fr; min-height: calc(100vh - 72px); }}
    aside {{ padding: 1rem; overflow-y: auto; border-right: 1px solid #334155; background: #1e293b; }}
    #graph {{ width: 100%; height: calc(100vh - 72px); background: #0f172a; }}
    h2 {{ font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin: 1.25rem 0 0.5rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; }}
    th, td {{ border-bottom: 1px solid #334155; padding: 0.4rem 0.3rem; text-align: left; vertical-align: top; }}
    th {{ color: #94a3b8; }}
    .pill {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; }}
    .owned {{ background: #14532d; color: #86efac; }}
    .pivot {{ background: #7c2d12; color: #fdba74; }}
    .next {{ background: #713f12; color: #fde68a; margin-top: 0.5rem; padding: 0.5rem; border-radius: 6px; font-size: 0.85rem; }}
    .blocker {{ background: #450a0a; color: #fecaca; margin-top: 0.5rem; padding: 0.5rem; border-radius: 6px; font-size: 0.85rem; }}
    code {{ background: #0f172a; padding: 0.1rem 0.25rem; border-radius: 3px; font-size: 0.78rem; }}
    .legend span {{ display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 4px; }}
    @media (max-width: 900px) {{ .layout {{ grid-template-columns: 1fr; }} aside {{ max-height: 40vh; }} }}
  </style>
</head>
<body>
  <header>
    <h1>ADMapper — Attack Graph</h1>
    <div class="meta">
      workspace <strong>{_esc(workspace)}</strong> · domain <strong>{_esc(domain_s)}</strong>
      · DC <strong>{_esc(dc_ip or '-')}</strong>
    </div>
  </header>
  <div class="layout">
    <aside>
      <h2>Estás aquí</h2>
      <p><span class="pill owned">owned</span> {_esc(', '.join(owned_users or []) or '(ninguno)')}</p>
      <p><span class="pill pivot">pivot</span> {_esc(pivot_user or '-')}</p>
      {next_hop_block}
      {blocker_block}
      <h2>Hash obtenido</h2>
      <table><thead><tr><th>cuenta</th><th>nthash</th><th>WinRM</th></tr></thead>
      <tbody>{hash_rows or '<tr><td colspan="3"><em>sin hash de máquina/gMSA</em></td></tr>'}</tbody></table>
      <h2>User match (LDAP · loot · enum)</h2>
      <table><thead><tr><th>user</th><th>AD</th><th>cred</th><th>sources</th></tr></thead>
      <tbody>{user_rows or '<tr><td colspan="4"><em>run start_auth / enum users</em></td></tr>'}</tbody></table>
      <h2>Pistas (loot)</h2>
      <table><thead><tr><th>user</th><th>string del archivo</th><th>estado</th><th>origen</th></tr></thead>
      <tbody>{clue_rows or '<tr><td colspan="4"><em>sin pistas</em></td></tr>'}</tbody></table>
      <h2>Leyenda</h2>
      <p class="legend">
        <span style="background:#22c55e"></span>owned
        <span style="background:#f97316"></span>pivot
        <span style="background:#ef4444"></span>high-value
        <span style="background:#06b6d4"></span>gMSA
        <span style="background:#8b5cf6"></span>group
      </p>
    </aside>
    <div id="graph"></div>
  </div>
  <script>
    const data = {graph_json};
    const container = document.getElementById('graph');
    const nodes = new vis.DataSet(data.nodes);
    const edges = new vis.DataSet(data.edges);
    const network = new vis.Network(container, {{ nodes, edges }}, {{
      physics: {{ stabilization: {{ iterations: 120 }}, barnesHut: {{ gravitationalConstant: -8000 }} }},
      interaction: {{ hover: true, tooltipDelay: 120 }},
      edges: {{ font: {{ color: '#cbd5e1', size: 10, strokeWidth: 0 }}, smooth: {{ type: 'dynamic' }} }},
      nodes: {{ shape: 'dot', size: 18, borderWidth: 2, shadow: true }},
    }});
    network.once('stabilizationIterationsDone', () => network.setOptions({{ physics: false }}));
  </script>
</body>
</html>"""


def write_attack_graph_html(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
) -> Path:
    out = ws_path / "attack_graph.html"
    out.write_text(
        build_attack_graph_html(
            ws_path,
            workspace=workspace,
            domain=domain,
            owned_users=owned_users,
            pivot_user=pivot_user,
        ),
        encoding="utf-8",
    )
    return out
