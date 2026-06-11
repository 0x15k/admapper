from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from admapper.models.ad_object import ComputerRecord, GroupRecord
from admapper.models.user import UserRecord


def export_bloodhound_minimal(
    path: Path,
    *,
    domain: str,
    users: list[UserRecord],
    groups: list[GroupRecord],
    computers: list[ComputerRecord],
) -> Path:
    """
    Phase 8.9 — minimal BloodHound CE-compatible JSON (users, groups, computers).

    Full ACL collection is out of scope; this seeds BH import with inventory nodes.
    """
    path.mkdir(parents=True, exist_ok=True)
    domain_upper = domain.upper()

    users_data = [
        {
            "ObjectIdentifier": f"{domain_upper}-{u.username.upper()}",
            "PrimaryGroupSID": None,
            "Properties": {
                "name": f"{u.username.upper()}@{domain_upper}",
                "domain": domain_upper,
                "domainsid": None,
                "distinguishedname": u.dn or "",
                "owned": False,
            },
        }
        for u in users
        if u.enabled and not u.is_machine_account
    ]

    groups_data = [
        {
            "ObjectIdentifier": f"{domain_upper}-{g.name.upper()}",
            "Properties": {
                "name": f"{g.name.upper()}@{domain_upper}",
                "domain": domain_upper,
                "distinguishedname": g.dn or "",
            },
        }
        for g in groups
    ]

    computers_data = [
        {
            "ObjectIdentifier": f"{domain_upper}-{c.name.upper()}",
            "Properties": {
                "name": f"{c.name.upper()}.{domain.lower()}",
                "domain": domain_upper,
                "distinguishedname": c.dn or "",
                "operatingsystem": c.operating_system or "",
            },
        }
        for c in computers
    ]

    _write_bh_file(path / "users.json", users_data, domain_upper, "users")
    _write_bh_file(path / "groups.json", groups_data, domain_upper, "groups")
    _write_bh_file(path / "computers.json", computers_data, domain_upper, "computers")
    return path


def _write_bh_file(
    file_path: Path,
    data: list[dict[str, Any]],
    domain: str,
    label: str,
) -> None:
    payload = {
        "data": data,
        "meta": {
            "type": label,
            "count": len(data),
            "version": 5,
            "collector": "admapper",
            "domain": domain,
        },
    }
    file_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
