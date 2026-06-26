from __future__ import annotations

"""Identity-scoped view — pivot profiles from workspace facts only (any lab)."""

from pathlib import Path
from typing import Any

from admapper.escalate.edges import collect_edges_from_pivot, pick_next_edge, sort_edges
from admapper.dashboard.ops_state import (
    _valid_cred_users,
    collect_identity_capabilities,
    collect_verified_missions,
)
from admapper.report.engagement import _load_json
from admapper.dashboard.ops_progress import OpsProgress, filtered_loot_clues
from admapper.report.scenario import _access_matrix_rows


def _owned_lower(owned: list[str]) -> set[str]:
    return {u.lower().rstrip("$") for u in owned}


def _user_node_id(username: str, domain: str) -> str:
    return f"user:{username.lower()}@{domain.lower()}"


_GLOBAL_ACTION_IDS = frozenset(
    {"scan", "cred", "enum", "enum_users", "asreproast", "kerberoast", "spray", "loot", "acls"}
)

METHOD_LABELS = {
    "password": "🔑 password",
    "ntlm_hash": "#️⃣ NTLM hash",
    "spray": "💨 spray",
    "kerberoast": "🎫 kerberoast",
    "asreproast": "🎫 AS-REP roast",
    "exploit_acl": "⚡ exploit ACL",
    "dll_hijack": "📦 DLL hijack",
    "winrm_pth": "#️⃣ WinRM PTH",
    "certificate": "📜 certificado",
}


def _normalize_account(name: str) -> str:
    base = str(name or "").strip().lower().rstrip("$")
    return base


def _machine_hash_row(ws_path: Path, username: str) -> dict[str, str] | None:
    from admapper.creds.common import collect_gained_hashes

    want = _normalize_account(username)
    if not want:
        return None
    for account, nthash in collect_gained_hashes(ws_path):
        if _normalize_account(account) == want and nthash:
            name = account if account.endswith("$") else f"{account}$"
            return {"username": name, "nthash": nthash}
    return None


def _lookup_inventory_user(ws_path: Path, username: str) -> dict[str, Any] | None:
    inv = (_load_json(ws_path / "auth_inventory.json") or {}).get("users") or []
    pl = username.lower()
    for u in inv:
        if str(u.get("username", "")).lower() == pl:
            return u
    return None


def _enum_flags(inv_user: dict[str, Any] | None) -> list[str]:
    if not inv_user:
        return []
    flags: list[str] = []
    if inv_user.get("kerberoastable"):
        flags.append("kerberoast")
    if inv_user.get("asrep_roastable"):
        flags.append("asrep")
    return flags


def _cred_status(ws_path: Path, username: str) -> str | None:
    creds = (_load_json(ws_path / "credentials.json") or {}).get("credentials") or []
    for c in creds:
        if str(c.get("username", "")).lower() != username.lower():
            continue
        return str(c.get("status") or "")
    return None


def build_selectable_identities(
    ws_path: Path,
    *,
    domain: str,
    owned_users: list[str],
    ops_progress: OpsProgress | None = None,
) -> list[dict[str, Any]]:
    """Humans the operator can focus on — owned, cred-valid, or loot-pending."""
    ws_path = Path(ws_path)
    owned = _owned_lower(owned_users)
    owned_methods: dict[str, str] = {}
    if ops_progress is not None:
        valid = ops_progress.verified_set()
        owned_methods = dict(ops_progress.owned_methods)
    else:
        valid = _valid_cred_users(ws_path)
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []

    def add(
        username: str,
        *,
        role: str,
        selectable: str,
        cred_valid: bool,
        detail: str = "",
        auth_method: str = "",
    ) -> None:
        key = username.lower()
        if not username or key in seen:
            return
        seen.add(key)
        rows.append(
            {
                "username": username,
                "node_id": _user_node_id(username, domain) if domain else "",
                "role": role,
                "selectable": selectable,
                "cred_valid": cred_valid,
                "owned": key.rstrip("$") in owned,
                "detail": detail,
                "auth_method": auth_method or owned_methods.get(key, ""),
            }
        )

    for user in sorted(owned_users, key=str.lower):
        method_key = owned_methods.get(user.lower(), "")
        method_label = METHOD_LABELS.get(method_key, method_key)
        method_part = f" · {method_label}" if method_label else ""
        cred_part = " · valid cred" if user.lower() in valid else " · no verified cred"
        add(
            user,
            role="owned",
            selectable="pivot",
            cred_valid=user.lower() in valid,
            detail=f"compromised{method_part}{cred_part}",
            auth_method=method_key,
        )

    for user in sorted(valid - owned):
        add(
            user,
            role="cred_valid",
            selectable="pivot",
            cred_valid=True,
            detail="valid credential — not marked owned",
        )

    for clue in filtered_loot_clues(ws_path, ops_progress):
        user = str(clue.get("user", ""))
        if not user or user.lower() in seen:
            continue
        if user.lower() in valid:
            continue
        add(
            user,
            role="loot_pending",
            selectable="verify",
            cred_valid=False,
            detail=f"clue in {str(clue.get('source', ''))[:40]}",
        )

    from admapper.creds.common import collect_gained_hashes
    for account, nthash in collect_gained_hashes(ws_path):
        if not nthash:
            continue
        name = account if account.endswith("$") else f"{account}$"
        add(
            name,
            role="machine_pth",
            selectable="pivot",
            cred_valid=True,
            detail="NTLM hash — WinRM Pass-the-Hash (no LDAP password)",
        )

    if ops_progress is not None and not ops_progress.enum_users:
        return rows

    inv = _load_json(ws_path / "auth_inventory.json") or {}
    for u in inv.get("users") or []:
        name = str(u.get("username", ""))
        if not name or name.lower() in seen or u.get("is_machine_account"):
            continue
        if name.lower() in {"krbtgt", "administrator", "guest"}:
            continue
        flags: list[str] = []
        if u.get("kerberoastable"):
            flags.append("kerberoast")
        if u.get("asrep_roastable"):
            flags.append("asrep")
        if not flags:
            continue
        add(
            name,
            role="enum_target",
            selectable="view",
            cred_valid=False,
            detail="enum target — " + ", ".join(flags),
        )

    return rows


def build_identity_lens(
    ws_path: Path,
    *,
    workspace: str,
    domain: str,
    pivot_user: str,
    owned_users: list[str],
    ops_progress: OpsProgress | None = None,
) -> dict[str, Any]:
    """Everything the UI should show for the active identity (pivot)."""
    ws_path = Path(ws_path)
    pivot = pivot_user.strip()
    owned = _owned_lower(owned_users)
    if ops_progress is not None:
        valid = ops_progress.verified_set()
    else:
        valid = _valid_cred_users(ws_path)
    pl = pivot.lower().rstrip("$")
    machine = _machine_hash_row(ws_path, pivot) if pivot.endswith("$") or "msa_" in pl else None
    if machine:
        from admapper.creds.common import format_admapper_winrm_pth

        account = machine["username"]
        nthash = machine["nthash"]
        _, winrm_cmd = format_admapper_winrm_pth(
            account=account,
            nthash=nthash,
            domain=domain,
            ws_path=ws_path,
        )
        return {
            "username": account,
            "node_id": f"gmsa:{pl}@{domain.lower()}",
            "status": "machine_pth",
            "status_label": "gMSA / machine — WinRM PTH (no LDAP password)",
            "read_only": False,
            "owned": True,
            "cred_valid": True,
            "cred_status": "nthash",
            "access_matrix": [account, "skip", "skip", "skip", "yes*", "gMSA hash — WinRM PTH"],
            "capabilities": [],
            "missions": [],
            "enabled_missions": [],
            "targets": [],
            "loot_clue": None,
            "inventory": {"dn": f"CN={pl},CN=Managed Service Accounts,DC={domain.replace('.', ',DC=')}"},
            "enum_flags": [],
            "edges": [],
            "next_edge": None,
            "is_machine": True,
            "nthash": nthash,
            "winrm_cmd": winrm_cmd,
        }

    capabilities: list[dict[str, Any]] = []
    for ident in collect_identity_capabilities(ws_path, domain=domain, owned_users=owned_users):
        if str(ident.get("username", "")).lower() == pl:
            capabilities = list(ident.get("capabilities") or [])
            break

    missions = [
        m
        for m in collect_verified_missions(
            ws_path, workspace=workspace, domain=domain, owned_users=owned_users
        )
        if str(m.get("principal", "")).lower() == pl
    ]
    enabled_missions = [m for m in missions if m.get("enabled")]

    edges = (
        collect_edges_from_pivot(
            pivot_user=pivot,
            owned_users=owned_users,
            ws_path=ws_path,
            domain=domain,
        )
        if pivot
        else []
    )
    next_edge = pick_next_edge(edges) if edges else None

    access_row: list[str] | None = None
    for row in _access_matrix_rows(ws_path):
        if str(row[0]).lower().rstrip("$") == pl.rstrip("$"):
            access_row = list(row)
            break

    targets: list[dict[str, Any]] = []
    for cap in capabilities:
        if cap.get("verified") or cap.get("enabled"):
            targets.append(
                {
                    "technique": cap.get("technique"),
                    "target": cap.get("target"),
                    "verified": cap.get("verified"),
                    "enabled": cap.get("enabled"),
                }
            )

    loot_clue = next(
        (c for c in filtered_loot_clues(ws_path, ops_progress) if str(c.get("user", "")).lower() == pl),
        None,
    )

    inv_user = _lookup_inventory_user(ws_path, pivot) if ops_progress is None or ops_progress.enum_users else None
    enum_flags = _enum_flags(inv_user)
    if ops_progress is not None and not ops_progress.acls:
        capabilities = []
        missions = []
        enabled_missions = []
        targets = []

    if pl in owned and pl in valid:
        status = "owned_ready"
        status_label = "Owned with credential — executable paths"
    elif pl in owned:
        status = "owned_no_cred"
        status_label = "Owned — missing valid credential"
    elif pl in valid:
        status = "cred_only"
        status_label = "Valid cred — mark owned or enumerate"
    elif loot_clue:
        status = "loot_pending"
        status_label = "Loot clue — verify password"
    elif enum_flags and pl not in owned and pl not in valid:
        status = "enum_target"
        status_label = "Enum target — " + ", ".join(enum_flags) + " (read-only)"
    else:
        status = "unknown"
        status_label = "No operational profile"

    read_only = status == "enum_target"
    inventory: dict[str, Any] | None = None
    if inv_user:
        inventory = {
            "enabled": inv_user.get("enabled"),
            "dn": inv_user.get("dn"),
            "groups": list(inv_user.get("groups") or [])[:8],
            "spn_count": len(inv_user.get("spns") or []),
        }

    return {
        "username": pivot,
        "node_id": _user_node_id(pivot, domain),
        "status": status,
        "status_label": status_label,
        "read_only": read_only,
        "owned": pl in owned,
        "cred_valid": pl in valid,
        "cred_status": _cred_status(ws_path, pivot),
        "access_matrix": access_row,
        "capabilities": capabilities,
        "missions": missions,
        "enabled_missions": enabled_missions,
        "primary_mission": enabled_missions[0] if enabled_missions else (missions[0] if missions else None),
        "outbound_edges": [e.to_dict() for e in sort_edges(edges)[:12]],
        "next_edge": next_edge.to_dict() if next_edge else None,
        "targets": targets[:8],
        "loot_clue": loot_clue,
        "enum_flags": enum_flags,
        "inventory": inventory,
    }


def filter_actions_for_pivot(
    actions: list[dict[str, Any]],
    *,
    pivot: str,
) -> list[dict[str, Any]]:
    """Keep workspace-wide steps plus missions/actions scoped to the active pivot."""
    if not pivot:
        return actions
    pl = pivot.lower()
    filtered: list[dict[str, Any]] = []
    for action in actions:
        aid = str(action.get("id") or "")
        if aid in _GLOBAL_ACTION_IDS:
            filtered.append(action)
            continue
        if aid == "verify_loot":
            principal = str(action.get("principal") or "").lower()
            if principal == pl:
                filtered.append(action)
            continue
        mission = action.get("mission") or {}
        principal = str(mission.get("principal") or "").lower()
        if principal and principal != pl:
            continue
        if mission or principal:
            filtered.append(action)
    return filtered if filtered else [a for a in actions if str(a.get("id") or "") in _GLOBAL_ACTION_IDS]


def filter_targets_for_pivot(
    targets: list[dict[str, Any]],
    *,
    pivot: str,
) -> list[dict[str, Any]]:
    """Target intel rows where the pivot principal appears in verified or graph paths."""
    if not pivot:
        return targets
    pl = pivot.lower().rstrip("$")
    filtered: list[dict[str, Any]] = []
    for row in targets:
        verified = row.get("direct_verified") or []
        graph_only = row.get("direct_graph_only") or []
        hit = any(pl in str(v).lower().split("(")[0].strip().rstrip("$") for v in verified)
        hit = hit or any(pl in str(v).lower() for v in graph_only)
        if hit:
            filtered.append(row)
    return filtered


def filter_intel_for_pivot(
    intel: dict[str, Any],
    pivot: str,
    lens: dict[str, Any],
) -> dict[str, Any]:
    """Keep global recon/lockout; narrow attack vectors to active identity."""
    pl = pivot.lower()
    vectors = list(intel.get("attack_readiness") or [])
    cap_techs = {str(c.get("technique", "")).lower() for c in lens.get("capabilities") or []}
    filtered: list[dict[str, Any]] = []
    for v in vectors:
        phase = str(v.get("phase") or "")
        aid = str(v.get("attack_id") or "")
        if phase in {"recon", "enum"}:
            filtered.append(v)
            continue
        if f":{pl}" in aid or aid.endswith(f":{pl}"):
            filtered.append(v)
            continue
        if phase == "escalate" and any(t in aid for t in cap_techs):
            filtered.append(v)
            continue
        if phase == "creds" and lens.get("status") in {"loot_pending", "cred_only", "owned_no_cred"}:
            if aid.startswith("creds_verify") or aid == "passwordspray":
                filtered.append(v)
            continue
        if phase == "kerberos" and lens.get("cred_valid"):
            filtered.append(v)
    intel = dict(intel)
    intel["attack_readiness"] = filtered or vectors[:12]
    intel["identity_focus"] = pivot
    return intel


def filter_attack_paths_for_pivot(
    paths: list[dict[str, Any]],
    pivot: str,
) -> list[dict[str, Any]]:
    """Narrow attack paths to those originating from the active pivot identity."""
    if not pivot:
        return paths
    pl = pivot.lower().rstrip("$")
    filtered: list[dict[str, Any]] = []
    for p in paths:
        src = str(p.get("source") or "").lower()
        src_label = str(p.get("source_label") or "").lower()
        if pl in src or pl == src_label.rstrip("$"):
            filtered.append(p)
    return filtered
