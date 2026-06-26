from __future__ import annotations

"""Progressive network topology (TryHackMe Networks / Grey Hack style).

Nodes and edges appear only from discovered workspace facts — blackbox safe.
"""

from pathlib import Path
from typing import Any

from admapper.report.engagement import _load_json

_PORT_LABELS: dict[int, str] = {
    88: "Kerberos :88",
    389: "LDAP :389",
    445: "SMB :445",
    636: "LDAPS :636",
    5985: "WinRM :5985",
    1433: "MSSQL :1433",
    9389: "ADWS :9389",
}


def _add_node(
    nodes: list[dict[str, Any]],
    seen: set[str],
    *,
    nid: str,
    label: str,
    group: str,
    color: str,
    x: float,
    y: float,
    shape: str = "box",
    size: int | None = None,
    title: str = "",
) -> None:
    if nid in seen:
        return
    seen.add(nid)
    node: dict[str, Any] = {
        "id": nid,
        "label": label,
        "group": group,
        "color": color,
        "x": x,
        "y": y,
        "fixed": {"x": True, "y": True},
        "shape": shape,
        "font": {"color": "#f8fafc", "size": 11},
        "title": title or label,
    }
    if size is not None:
        node["size"] = size
    nodes.append(node)


def _add_edge(
    edges: list[dict[str, Any]],
    seen: set[str],
    *,
    eid: str,
    src: str,
    tgt: str,
    label: str = "",
    color: str = "#4a5568",
    dashes: bool = False,
    width: int = 2,
) -> None:
    if eid in seen:
        return
    seen.add(eid)
    edges.append(
        {
            "id": eid,
            "from": src,
            "to": tgt,
            "label": label,
            "color": {"color": color},
            "dashes": dashes,
            "width": width,
            "smooth": {"type": "curvedCW", "roundness": 0.15},
        }
    )


def build_network_topology(
    ws_path: Path,
    *,
    domain: str | None,
    owned_users: list[str] | None = None,
    reveal_scan: bool = True,
    reveal_enum: bool = True,
) -> dict[str, Any]:
    """Build THM-style infra map from scan → enum → owned discoveries."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    n_seen: set[str] = set()
    e_seen: set[str] = set()
    discoveries: list[str] = []

    owned = list(owned_users or [])
    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    inv = _load_json(ws_path / "auth_inventory.json") or {}
    has_scan = bool(unauth.get("hosts")) and reveal_scan

    _add_node(
        nodes,
        n_seen,
        nid="operator",
        label="YOU\n(workstation)",
        group="operator",
        color="#3dffcf",
        x=-420,
        y=0,
        shape="box",
        title="Your position — no visibility until you scan",
    )

    if not has_scan:
        _add_node(
            nodes,
            n_seen,
            nid="unknown",
            label="???\n(not scanned)",
            group="unknown",
            color="#374151",
            x=120,
            y=0,
            shape="dot",
            size=28,
            title="Enter an IP and run recon",
        )
        _add_edge(
            edges,
            e_seen,
            eid="op-unknown",
            src="operator",
            tgt="unknown",
            label="",
            color="#374151",
            dashes=True,
        )
        return {
            "nodes": nodes,
            "edges": edges,
            "mode": "blackbox",
            "discovery_pct": 0,
            "discoveries": discoveries,
            "has_scan": False,
        }

    discovered_domain = str(unauth.get("domain") or "").strip()
    domain_known = bool(discovered_domain and discovered_domain not in {"(no domain)", "?"})
    if domain_known:
        discoveries.append(f"Domain: {discovered_domain}")

    dc_id: str | None = None
    targets: list[dict[str, Any]] = []
    host_rows = unauth.get("hosts") or []
    for idx, host in enumerate(host_rows):
        addr = str(host.get("address", ""))
        if not addr:
            continue
        is_dc = bool(host.get("is_domain_controller"))
        hostname = str(host.get("hostname") or "")
        hn_show = hostname if hostname and hostname not in {"-", "?"} else "desconocido"
        role = "DOMAIN CONTROLLER" if is_dc else "HOST"
        ports = list(host.get("open_ports") or [])[:12]
        services = [
            {"port": int(port), "label": _PORT_LABELS.get(int(port), f"TCP/{port}")}
            for port in ports
        ]
        svc_short = " · ".join(s["label"] for s in services[:6]) if services else "sin puertos abiertos"
        label = f"{role}\n{addr}"
        hx = 80 + idx * 220
        hid = f"host:{addr}"
        if is_dc:
            dc_id = hid
        _add_node(
            nodes,
            n_seen,
            nid=hid,
            label=label,
            group="dc" if is_dc else "host",
            color="#6366f1" if is_dc else "#64748b",
            x=hx,
            y=0,
            shape="box",
            title=f"{hn_show}\n{svc_short}",
        )
        _add_edge(
            edges,
            e_seen,
            eid=f"op-{addr}",
            src="operator",
            tgt=hid,
            label="recon",
            color="#3dffcf",
            width=3,
        )
        discoveries.append(f"Host {addr} ({hn_show})")
        if services:
            discoveries.append(f"Servicios {addr}: {svc_short}")
        targets.append(
            {
                "id": hid,
                "address": addr,
                "hostname": hn_show,
                "role": role,
                "is_dc": is_dc,
                "services": services,
            }
        )
        for port in ports:
            if int(port) == 88:
                discoveries.append(f"Kerberos KDC en {addr}")
            elif int(port) == 389:
                discoveries.append(f"LDAP en {addr}")
            elif int(port) == 445:
                discoveries.append(f"SMB en {addr}")

    if domain_known and dc_id:
        dc_host = ""
        for host in host_rows:
            if host.get("is_domain_controller"):
                dc_host = str(host.get("hostname") or "")
                break
        if not dc_host:
            dc_host = discovered_domain.split(".")[0] if discovered_domain else ""
        _add_node(
            nodes,
            n_seen,
            nid="domain",
            label=f"AD DOMAIN\n{discovered_domain}",
            group="domain",
            color="#8b5cf6",
            x=80 + len(host_rows) * 220 + 40,
            y=-160,
            shape="ellipse",
        )
        _add_edge(
            edges,
            e_seen,
            eid="dc-domain",
            src=dc_id,
            tgt="domain",
            label=dc_host or "RootDSE",
            color="#8b5cf6",
            width=2,
        )

    computers = inv.get("computers") or [] if reveal_enum else []
    enum_hosts = [c for c in computers if not str(c.get("name", "")).lower().startswith("msa_")][:8]
    for ci, comp in enumerate(enum_hosts):
        name = str(comp.get("name") or comp.get("dns_host") or "")
        if not name:
            continue
        dns = str(comp.get("dns_host") or name)
        cy = 180 + (ci % 4) * 70
        cx = 40 + (ci // 4) * 200
        cid = f"computer:{name.lower()}"
        _add_node(
            nodes,
            n_seen,
            nid=cid,
            label=f"PC\n{name[:20]}",
            group="computer",
            color="#475569",
            x=cx,
            y=cy,
            size=20,
            shape="dot",
        )
        if dc_id:
            _add_edge(
                edges,
                e_seen,
                eid=f"dc-{cid}",
                src=dc_id,
                tgt=cid,
                label="member",
                color="#475569",
                dashes=True,
            )
        discoveries.append(f"Equipo enum: {name}")

    gmsa = [
        c
        for c in computers
        if "managed service accounts" in str(c.get("dn", "")).lower()
        or str(c.get("name", "")).lower().startswith("msa_")
    ]
    for gi, g in enumerate(gmsa[:4]):
        name = str(g.get("name") or "")
        gid = f"gmsa:{name.lower()}"
        _add_node(
            nodes,
            n_seen,
            nid=gid,
            label=f"gMSA\n{name}",
            group="gmsa",
            color="#06b6d4",
            x=320 + gi * 140,
            y=200,
            shape="dot",
            size=22,
        )
        if dc_id:
            _add_edge(
                edges,
                e_seen,
                eid=f"dc-{gid}",
                src=dc_id,
                tgt=gid,
                label="gMSA",
                color="#06b6d4",
            )
        discoveries.append(f"gMSA: {name}")

    max_steps = 12
    pct = min(100, int(len(discoveries) / max_steps * 100))

    return {
        "nodes": nodes,
        "edges": edges,
        "mode": "network",
        "discovery_pct": pct,
        "discoveries": discoveries[-16:],
        "targets": targets,
        "has_scan": True,
        "domain_known": domain_known,
        "domain": discovered_domain if domain_known else None,
    }
