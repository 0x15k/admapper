from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from admapper.creds.common import pick_dc_ip
from admapper.guides.render import print_manual_guide
from admapper.support.output import (
    ConfirmLevel,
    confirm,
    print_info,
    print_success,
    print_table,
    print_warning,
)

if TYPE_CHECKING:
    from admapper.support.session import Session


@dataclass
class TimeroastTarget:
    computer: str
    dns_host: str | None = None
    dn: str | None = None

    def to_dict(self) -> dict:
        return {
            "computer": self.computer,
            "dns_host": self.dns_host,
            "dn": self.dn,
        }


@dataclass
class TimeroastResult:
    domain: str
    dc_ip: str
    targets: list[TimeroastTarget] = field(default_factory=list)
    output_path: str | None = None
    external_tool: str | None = None


def _load_computer_targets(session: Session) -> list[TimeroastTarget]:
    ws_name = session.workspace.name  # type: ignore[union-attr]
    inv_path = session.workspaces.path_for(ws_name) / "auth_inventory.json"
    if not inv_path.is_file():
        return []
    data = json.loads(inv_path.read_text(encoding="utf-8"))
    targets: list[TimeroastTarget] = []
    for computer in data.get("computers") or []:
        name = str(computer.get("name", ""))
        if not name:
            continue
        targets.append(
            TimeroastTarget(
                computer=name,
                dns_host=computer.get("dns_host"),
                dn=computer.get("dn"),
            )
        )
    return targets


def _resolve_timeroast_tool() -> str | None:
    for name in ("timeroast", "timeroast.py"):
        if shutil.which(name):
            return name
    return None


def run_timeroast(session: Session) -> TimeroastResult:
    """Phase 11.1 — enumerate timeroast candidates and optionally invoke external tool."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before timeroast")

    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC — run start_unauth first")

    targets = _load_computer_targets(session)
    if not targets:
        raise ValueError("no computer inventory — run start_auth first")

    if not confirm(
        f"Timeroast prep: {len(targets)} machine account(s) @ {dc_ip}?",
        level=ConfirmLevel.WARN,
        mode_auto=session.mode.value == "auto",
        mode_manual=session.mode.value == "manual",
    ):
        print_warning("timeroast cancelled")
        return TimeroastResult(domain=domain, dc_ip=dc_ip)

    print_info(f"Phase 11.1 — timeroast candidates ({len(targets)} computers)")

    ws_path = session.workspaces.path_for(session.workspace.name)
    out_path = ws_path / "timeroast_targets.json"
    payload = {
        "domain": domain,
        "dc_ip": dc_ip,
        "target_count": len(targets),
        "targets": [t.to_dict() for t in targets],
        "note": "Use external timeroast tool — ADMapper exports candidates + guide",
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    rows = [[t.computer, t.dns_host or ""] for t in targets[:15]]
    print_table("Timeroast targets (sample)", ["computer", "dns_host"], rows)

    tool = _resolve_timeroast_tool()
    if tool:
        print_info(f"external tool on PATH: {tool} — run manually with workspace creds")
    else:
        print_warning("no timeroast binary on PATH — see guide timeroasting")

    print_success("targets saved → timeroast_targets.json")
    print_manual_guide("timeroasting", session=session)
    return TimeroastResult(
        domain=domain,
        dc_ip=dc_ip,
        targets=targets,
        output_path=str(out_path),
        external_tool=tool,
    )
