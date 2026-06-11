from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class WsusPrerequisite:
    key: str
    label: str
    met: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "met": self.met,
            "detail": self.detail,
        }


def owned_groups_for_user(inventory: dict[str, Any] | None, username: str) -> list[str]:
    """Return group names where username is a member (from auth_inventory)."""
    if not inventory:
        return []
    user_dn = None
    for user in inventory.get("users") or []:
        if str(user.get("username", "")).lower() == username.lower():
            user_dn = str(user.get("dn") or "")
            break
    if not user_dn:
        return []
    groups: list[str] = []
    for group in inventory.get("groups") or []:
        members = [str(m) for m in group.get("members") or []]
        if user_dn in members:
            groups.append(str(group.get("name") or ""))
    return groups


def check_wsus_prerequisites(
    *,
    username: str,
    groups: list[str],
    has_adcs: bool,
    wsus_share: bool,
    enroll_findings: list[dict[str, Any]],
    acl_findings: list[dict[str, Any]],
    require_enrollment: bool = False,
    require_wsus_path: bool = False,
) -> list[WsusPrerequisite]:
    checks: list[WsusPrerequisite] = [
        WsusPrerequisite(
            key="owned_user",
            label=f"Owned user: {username}",
            met=True,
        ),
        WsusPrerequisite(
            key="adcs_present",
            label="AD CS enumerated",
            met=has_adcs,
            detail="run: admapper adcs",
        ),
        WsusPrerequisite(
            key="wsus_share",
            label="WSUSTemp share discovered",
            met=wsus_share,
            detail="WSUS content share on DC (check share_loot / start_auth)",
        ),
    ]

    in_it = "IT" in groups
    in_wsus_admin = "WSUS Administrators" in groups
    checks.append(
        WsusPrerequisite(
            key="privileged_group",
            label="IT or WSUS Administrators membership",
            met=in_it or in_wsus_admin,
            detail=f"groups: {', '.join(groups) or 'none'}",
        )
    )

    user_enroll = any(
        str(f.get("principal", "")).lower() == username.lower() for f in enroll_findings
    )
    checks.append(
        WsusPrerequisite(
            key="template_enrollment",
            label="Restricted template enrollment for owned user",
            met=user_enroll,
            detail="run: admapper adcs (after owning pivot user)",
        )
    )

    wsus_acl = any(
        str(f.get("principal", "")).lower() == username.lower()
        and str(f.get("right")) in ("addmember", "genericall", "genericwrite")
        and "wsus" in str(f.get("target_name", "")).lower()
        for f in acl_findings
    )
    checks.append(
        WsusPrerequisite(
            key="wsus_acl",
            label="ACL abuse path to WSUS Administrators",
            met=wsus_acl,
            detail="run: admapper acls as owned user",
        )
    )

    if require_enrollment:
        checks = [c for c in checks if c.key in ("owned_user", "adcs_present", "template_enrollment")]
    if require_wsus_path:
        checks = [
            c
            for c in checks
            if c.key
            in ("owned_user", "adcs_present", "wsus_share", "privileged_group", "wsus_acl", "template_enrollment")
        ]

    return checks
