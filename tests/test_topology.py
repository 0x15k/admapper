from __future__ import annotations

import json
from pathlib import Path

from admapper.graph.topology import build_network_topology


def test_blackbox_topology_empty(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    topo = build_network_topology(ws, domain=None, owned_users=[])
    assert topo["has_scan"] is False
    assert topo["discovery_pct"] == 0
    assert any(n["id"] == "unknown" for n in topo["nodes"])


def test_topology_after_scan(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "unauth_scan.json").write_text(
        json.dumps(
            {
                "domain": "logging.htb",
                "hosts": [
                    {
                        "address": "10.129.1.1",
                        "hostname": "dc01.logging.htb",
                        "is_domain_controller": True,
                        "open_ports": [88, 389, 445],
                    }
                ],
            }
        )
    )
    topo = build_network_topology(ws, domain="logging.htb", owned_users=[])
    assert topo["has_scan"] is True
    assert topo["domain_known"] is True
    assert any(n["id"] == "host:10.129.1.1" for n in topo["nodes"])
    assert topo["targets"][0]["services"]
    assert any("Kerberos" in d for d in topo["discoveries"])
