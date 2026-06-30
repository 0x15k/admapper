"""Resolve scheduled-task run-as principal from scan artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from admapper.postex.hijack_intel import _normalize_run_as, is_system_run_as

# Service/product names that appear in logs but are not interactive task principals.
_NON_USER_RUN_AS = frozenset(
    {
        "unknown",
        "scheduled_task",
        "scheduled task",
        "updatemonitor",
        "sentinel",
    }
)


def load_enumerated_usernames(ws_path: Path | str | None) -> frozenset[str]:
    """Domain users from users.json / auth_inventory.json (lowercase sAM names)."""
    if ws_path is None:
        return frozenset()
    root = Path(ws_path)
    names: set[str] = set()

    for filename in ("auth_inventory.json", "users.json"):
        path = root / filename
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for item in data.get("users") or []:
            if isinstance(item, str):
                name = item.strip()
            elif isinstance(item, dict):
                name = str(item.get("username") or item.get("samaccountname") or "").strip()
            else:
                continue
            if name:
                names.add(name.lower())

    return frozenset(names)


def is_service_principal_name(username: str) -> bool:
    return _normalize_run_as(username).lower().rstrip("$") in _NON_USER_RUN_AS


def is_interactive_task_user(
    run_as: str,
    *,
    enum_users: frozenset[str] | None = None,
    from_task_scan: bool = False,
) -> bool:
    user = _normalize_run_as(run_as).lower().rstrip("$")
    if not user or user in _NON_USER_RUN_AS:
        return False
    if is_system_run_as(user):
        return False
    if from_task_scan:
        return True
    if enum_users and user not in enum_users and f"{user}$" not in enum_users:
        return False
    return True


def is_cred_panel_user(
    username: str,
    *,
    enum_users: frozenset[str],
    has_stored_secret: bool = False,
) -> bool:
    """Hide service-name noise and unverified synthetic creds when enum exists."""
    name = str(username or "").strip()
    if not name:
        return False
    if is_service_principal_name(name):
        return False
    if name.endswith("$"):
        return True
    base = _normalize_run_as(name).lower()
    if not enum_users:
        return True
    if base in enum_users:
        return True
    return has_stored_secret


def _task_matches_hint(task: dict, *, task_hint: str, payload_zip: str) -> bool:
    name = str(task.get("name") or "").lower()
    exe = str(task.get("executable") or "").lower()
    args = str(task.get("arguments") or "").lower()
    hint = task_hint.lower()
    zip_lower = payload_zip.lower()
    if hint and hint in name:
        return True
    if "updatemonitor" in exe:
        return True
    if zip_lower and zip_lower in args:
        return True
    if zip_lower and zip_lower in exe:
        return True
    return not hint and not zip_lower


def resolve_task_run_as(
    scan: dict,
    finding: dict | None = None,
    *,
    ws_path: Path | str | None = None,
    enum_users: frozenset[str] | None = None,
) -> str:
    """Return the user the scheduled task runs as (not the WinRM upload principal)."""
    if enum_users is None:
        enum_users = load_enumerated_usernames(ws_path)

    finding = finding or {}
    hinted = str(finding.get("run_as_user") or "").strip()
    if is_interactive_task_user(hinted, enum_users=enum_users):
        return _normalize_run_as(hinted)

    task_hint = str(finding.get("task_name") or "").strip()
    payload_zip = str(finding.get("payload_zip") or "").strip()
    tasks = scan.get("tasks") if isinstance(scan.get("tasks"), list) else []

    for task in tasks:
        if not isinstance(task, dict):
            continue
        if task_hint or payload_zip:
            if not _task_matches_hint(task, task_hint=task_hint, payload_zip=payload_zip):
                continue
        run_as = str(task.get("run_as") or "").strip()
        if is_interactive_task_user(run_as, enum_users=enum_users, from_task_scan=True):
            return _normalize_run_as(run_as)

    for line in str(scan.get("com_task_raw") or "").splitlines():
        if "|" not in line:
            continue
        parts = line.split("|", 3)
        if len(parts) < 2:
            continue
        run_as = parts[1].strip()
        if task_hint or payload_zip:
            task_line = {
                "name": parts[0].strip(),
                "executable": parts[2].strip() if len(parts) > 2 else "",
                "arguments": parts[3].strip() if len(parts) > 3 else "",
            }
            if not _task_matches_hint(task_line, task_hint=task_hint, payload_zip=payload_zip):
                continue
        if is_interactive_task_user(run_as, enum_users=enum_users, from_task_scan=True):
            return _normalize_run_as(run_as)

    for task in tasks:
        if not isinstance(task, dict):
            continue
        run_as = str(task.get("run_as") or "").strip()
        if is_interactive_task_user(run_as, enum_users=enum_users, from_task_scan=True):
            return _normalize_run_as(run_as)

    if hinted and is_interactive_task_user(hinted, enum_users=enum_users):
        result = _normalize_run_as(hinted)
    else:
        result = "unknown"
    return result
