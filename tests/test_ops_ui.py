from __future__ import annotations

import json
import threading
from http.client import HTTPConnection
from pathlib import Path

from admapper.graph.dashboard_server import DashboardContext, make_handler
from admapper.graph.ops_ui import build_ops_html, build_ops_payload, write_ops_html
from admapper.graph.web import filter_tactical_graph
from http.server import ThreadingHTTPServer


def _minimal_ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps(
            {
                "hosts": [
                    {
                        "address": "10.0.0.1",
                        "hostname": "dc01.corp.local",
                        "is_domain_controller": True,
                        "open_ports": [88, 389, 445],
                    }
                ]
            }
        )
    )
    (ws / "credentials.json").write_text(
        json.dumps(
            {
                "credentials": [
                    {
                        "username": "alice",
                        "status": "valid",
                        "source": "run",
                    }
                ]
            }
        )
    )
    (ws / "auth_inventory.json").write_text("{}")
    return ws


def test_build_ops_payload_phases(tmp_path: Path) -> None:
    ws = _minimal_ws(tmp_path)
    data = build_ops_payload(ws, workspace="ws", domain="corp.local", owned_users=["alice"])
    assert data["meta"]["dc_ip"] == "10.0.0.1"
    assert len(data["phases"]) == 9
    assert "study_map" in data
    assert len(data["study_map"]) == 12
    assert data["phases"][0]["code"] == "RECON"
    assert data["phases"][0]["status"] == "done"
    foothold = next(p for p in data["phases"] if p["code"] == "FOOTHOLD")
    assert foothold["status"] == "done"
    assert "graph" in data
    assert len(data["graph"]["nodes"]) >= 1
    assert "engagement_intel" in data
    assert "lockout_policy" in data["engagement_intel"]
    assert "domain_users" in data["engagement_intel"]
    assert "attack_readiness" in data["engagement_intel"]
    assert "pentest_book" in data
    assert data["pentest_book"]["page_count"] >= 10
    assert "selectable_identities" in data
    assert "identity_lens" in data
    assert "operator_setup" in data


def test_build_ops_payload_recon_placeholder_nodes(tmp_path: Path) -> None:
    ws = tmp_path / "empty"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps({"hosts": [{"address": "10.9.9.9", "is_domain_controller": True}]})
    )
    data = build_ops_payload(ws, workspace="empty", domain="lab.local")
    nodes = data["graph"]["nodes"]
    assert any("OPERATOR" in str(n.get("label", "")) for n in nodes)
    assert any("10.9.9.9" in str(n.get("title", "")) for n in nodes)


def test_build_ops_html_real_terms(tmp_path: Path) -> None:
    ws = _minimal_ws(tmp_path)
    html = build_ops_html(ws, workspace="ws", domain="corp.local", pivot_user="alice", api_mode=True)
    assert "AD OPS" in html
    assert "Kerberos" in html
    assert "GenericWrite" in html
    assert "vis.Network" in html
    assert "screen-boot" in html
    assert "boot-ip" in html
    assert "tab-network" in html
    assert "screen-play" in html
    assert "ESCANEAR" in html
    assert "CRTP" in html
    assert "TERMINAL" in html
    assert "NOTAS" in html
    assert "note-kv" in html
    assert "note-arr" in html
    assert "Prerrequisitos por ataque" in html
    assert "MANUAL" in html
    assert "book-reader" in html
    assert "Identidades" in html
    assert "AUTENTICAR" in html
    assert "CONECTAR WINRM PTH" in html
    assert "screen-hq" in html
    assert "hq-canvas" in html
    assert "tab-hq" in html
    assert "Política de bloqueo" in html
    assert "Usuarios del dominio" in html
    assert "Análisis de pista" in html


def test_write_ops_html(tmp_path: Path) -> None:
    ws = _minimal_ws(tmp_path)
    out = write_ops_html(ws, workspace="ws", domain="corp.local")
    assert out.name == "ad_ops.html"
    assert out.exists()


def test_build_ops_payload_includes_mission(tmp_path: Path) -> None:
    ws = _minimal_ws(tmp_path)
    (ws / "acl_findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "principal": "alice",
                        "target_name": "msa_health",
                        "right": "genericwrite",
                        "severity": "high",
                        "summary": "Add self to gMSA admins",
                        "id": "acl-001",
                    }
                ]
            }
        )
    )
    data = build_ops_payload(
        ws, workspace="ws", domain="corp.local", owned_users=["alice"], pivot_user="alice"
    )
    assert data["mission"] is not None
    assert data["mission"]["action"] == "exploit"
    assert "genericwrite" in data["mission"]["technique"].lower()


def test_filter_tactical_graph_hides_orphan_groups() -> None:
    payload = {
        "nodes": [
            {"id": "a", "label": "★ alice", "group": "user"},
            {"id": "b", "label": "orphan-group", "group": "group"},
            {"id": "c", "label": "msa_health", "group": "computer"},
        ],
        "edges": [{"from": "a", "to": "c", "label": "genericwrite"}],
        "pivot": "alice",
        "owned": ["alice"],
    }
    out = filter_tactical_graph(payload)
    assert out["hidden_nodes"] == 1
    assert len(out["nodes"]) == 2
    assert any(n["id"] == "a" for n in out["nodes"])


def test_build_ops_payload_filters_actions_by_pivot(tmp_path: Path) -> None:
    ws = _minimal_ws(tmp_path)
    (ws / "auth_inventory.json").write_text(
        json.dumps(
            {
                "users": [
                    {"username": "alice", "enabled": True},
                    {"username": "bob", "enabled": True},
                ]
            }
        )
    )
    (ws / "acl_findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "principal": "alice",
                        "target_name": "target_a",
                        "right": "genericwrite",
                        "severity": "high",
                        "summary": "alice path",
                        "id": "acl-a",
                    },
                    {
                        "principal": "bob",
                        "target_name": "target_b",
                        "right": "genericwrite",
                        "severity": "high",
                        "summary": "bob path",
                        "id": "acl-b",
                    },
                ]
            }
        )
    )
    data = build_ops_payload(
        ws,
        workspace="ws",
        domain="corp.local",
        owned_users=["alice", "bob"],
        pivot_user="alice",
    )
    principals = {
        str((a.get("mission") or {}).get("principal", "")).lower()
        for a in data["actions"]
        if a.get("mission")
    }
    assert principals <= {"alice", ""}
    assert all(q.get("principal") == "alice" for q in data["quests"] if q.get("principal"))


def test_build_ops_payload_view_lens_on_enum_user(tmp_path: Path) -> None:
    ws = _minimal_ws(tmp_path)
    (ws / "auth_inventory.json").write_text(
        json.dumps(
            {
                "users": [
                    {"username": "alice", "enabled": True},
                    {"username": "carol", "enabled": True, "kerberoastable": True},
                ]
            }
        )
    )
    data = build_ops_payload(
        ws, workspace="ws", domain="corp.local", owned_users=["alice"], pivot_user="alice"
    )
    carol = next(r for r in data["selectable_identities"] if r["username"] == "carol")
    assert carol["selectable"] == "view"
    assert carol["view_lens"]["status"] == "enum_target"
    assert carol["view_lens"]["read_only"] is True


def test_build_ops_payload_includes_operator_setup(tmp_path: Path) -> None:
    ws = _minimal_ws(tmp_path)
    data = build_ops_payload(ws, workspace="ws", domain="corp.local", owned_users=[])
    assert "operator_setup" in data
    assert data["operator_setup"]["sync_dc_cmd"] is None or "sync-dc" in data["operator_setup"]["sync_dc_cmd"]


def test_dashboard_server_state_endpoint(tmp_path: Path) -> None:
    ws = _minimal_ws(tmp_path)
    ctx = DashboardContext(
        ws_path=ws,
        workspace="ws",
        domain="corp.local",
        owned_users=["alice"],
        pivot_user="alice",
        host="10.0.0.1",
    )
    handler = make_handler(ctx)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/state")
        resp = conn.getresponse()
        assert resp.status == 200
        body = json.loads(resp.read().decode("utf-8"))
        assert body["meta"]["workspace"] == "ws"
        assert body["phases"][0]["code"] == "RECON"
        conn.close()

        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/")
        resp = conn.getresponse()
        assert resp.status == 200
        html = resp.read().decode("utf-8")
        assert "ADMapper" in html
        assert "vis-network" in html
        conn.close()
    finally:
        httpd.shutdown()
