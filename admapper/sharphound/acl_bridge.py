"""Merge SharpHound BloodHound-CE JSON into pivot-scoped attack intel.

After ``import_sharphound_zip()`` writes ``bloodhound/sh_*.json``, this module
extracts outbound ACEs for the collecting user (and their group SIDs) into
``acl_findings.json``, syncs pivot/owned state, and refreshes ``escalate.json``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from admapper.acl.rights import abuse_right
from admapper.models.ad_object import AclAbuseFinding
from admapper.support.output import print_info, print_success, print_warning

if TYPE_CHECKING:
    from admapper.support.session import Session

_SKIP_JSON = frozenset({"collection_manifest.json", "bloodhound_overlay.json"})
_SH_PREFIX = "sh_"

# BloodHound RightName → internal abuse key (``admapper.acl.rights``).
_RIGHT_MAP: dict[str, str] = {
    "GenericAll": "genericall",
    "GenericWrite": "genericwrite",
    "WriteDacl": "writedacl",
    "WriteOwner": "writeowner",
    "ForceChangePassword": "forcechangepassword",
    "AddMember": "addmember",
    "AllExtendedRights": "allextendedrights",
    "Owns": "owns",
    "ReadLAPSPassword": "readlapspassword",
    "ReadGMSAPassword": "readgmsapassword",
    "WriteSPN": "writespn",
    "GetChanges": "dcsync",
    "GetChangesAll": "dcsync",
    "WriteAccountRestrictions": "genericwrite",
    "Self": "addmember",
}

_INTERESTING_RIGHTS = frozenset(_RIGHT_MAP) | frozenset({"Enroll", "ExtendedRight"})


def _type_from_filename(name: str) -> str:
    n = name.lower()
    if "users" in n:
        return "user"
    if "groups" in n:
        return "group"
    if "computers" in n:
        return "computer"
    if "domains" in n:
        return "domain"
    if "gpos" in n:
        return "gpo"
    if "ous" in n:
        return "ou"
    if "certtemplates" in n:
        return "certtemplate"
    if "containers" in n:
        return "container"
    return "base"


def _normalize_username(value: str) -> str:
    text = str(value or "").strip()
    if "@" in text:
        text = text.split("@", 1)[0]
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    return text.lower()


def _username_from_bh_name(name: str) -> str:
    """``JAYLEE.CLIFTON@LOGGING.HTB`` → ``jaylee.clifton``."""
    text = str(name or "").strip()
    if "@" in text:
        text = text.split("@", 1)[0]
    return text.lower()


def _load_bh_objects(bh_dir: Path) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]:
    """Return (objects, sid→label, username→sid) from ``bloodhound/sh_*.json``."""
    objects: list[dict[str, Any]] = []
    sid_to_label: dict[str, str] = {}
    user_to_sid: dict[str, str] = {}

    for path in sorted(bh_dir.glob(f"{_SH_PREFIX}*.json")):
        if path.name in _SKIP_JSON:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        obj_type = _type_from_filename(path.name)
        for obj in payload.get("data") or []:
            if not isinstance(obj, dict):
                continue
            props = obj.get("Properties") if isinstance(obj.get("Properties"), dict) else {}
            sid = str(obj.get("ObjectIdentifier") or props.get("objectid") or "")
            label = str(props.get("name") or props.get("distinguishedname") or sid)
            if sid:
                sid_to_label[sid] = label
            if obj_type == "user" and sid:
                user_to_sid[_username_from_bh_name(label)] = sid
            objects.append({"type": obj_type, "obj": obj, "label": label, "sid": sid})

    return objects, sid_to_label, user_to_sid


def _group_sids_for_user(objects: list[dict[str, Any]], user_sid: str) -> set[str]:
    """Direct group memberships from SharpHound ``Members`` arrays."""
    groups: set[str] = set()
    for item in objects:
        if item["type"] != "group":
            continue
        group_sid = item["sid"]
        if not group_sid:
            continue
        for member in item["obj"].get("Members") or []:
            if not isinstance(member, dict):
                continue
            mid = str(member.get("ObjectIdentifier") or member.get("MemberId") or "")
            if mid == user_sid:
                groups.add(group_sid)
    return groups


def _principal_sids(
    pivot_user: str,
    *,
    user_to_sid: dict[str, str],
    objects: list[dict[str, Any]],
) -> tuple[str, set[str]]:
    pivot_l = _normalize_username(pivot_user)
    user_sid = user_to_sid.get(pivot_l, "")
    sids: set[str] = set()
    if user_sid:
        sids.add(user_sid)
        sids.update(_group_sids_for_user(objects, user_sid))
    return user_sid, sids


def _finding_from_ace(
    *,
    pivot_user: str,
    principal_sid: str,
    sid_to_label: dict[str, str],
    target_type: str,
    target_name: str,
    target_dn: str,
    target_sid: str,
    right_name: str,
) -> AclAbuseFinding | None:
    if right_name not in _INTERESTING_RIGHTS:
        return None
    key = _RIGHT_MAP.get(right_name, right_name.lower())
    meta = abuse_right(key)
    trustee = sid_to_label.get(principal_sid, principal_sid)
    summary = meta.exploit_summary
    if right_name == "Enroll":
        summary = f"Certificate enrollment right on {target_name} (SharpHound collect)."
    return AclAbuseFinding(
        right=key,
        principal=pivot_user,
        trustee_sid=principal_sid,
        trustee_name=trustee,
        target_dn=target_dn,
        target_name=target_name,
        target_type=target_type,
        severity=meta.severity,
        mitre_id=meta.mitre_id,
        summary=summary,
        manual_commands=list(meta.manual_commands),
    )


def extract_sharphound_acl_findings(
    ws_path: Path,
    pivot_user: str,
    *,
    domain: str | None = None,
) -> list[AclAbuseFinding]:
    """Outbound abuse ACEs for *pivot_user* (+ group SIDs) from ``bloodhound/sh_*.json``."""
    bh_dir = ws_path / "bloodhound"
    if not bh_dir.is_dir():
        return []

    objects, sid_to_label, user_to_sid = _load_bh_objects(bh_dir)
    if not objects:
        return []

    _, principal_sids = _principal_sids(pivot_user, user_to_sid=user_to_sid, objects=objects)
    if not principal_sids:
        print_warning(f"SharpHound: no SID for pivot {pivot_user!r} — ACL bridge skipped")
        return []

    findings: list[AclAbuseFinding] = []
    seen: set[tuple[str, str, str, str]] = set()

    for item in objects:
        obj = item["obj"]
        props = obj.get("Properties") if isinstance(obj.get("Properties"), dict) else {}
        target_sid = str(item["sid"] or "")
        target_name = str(item["label"] or target_sid)
        target_dn = str(props.get("distinguishedname") or props.get("name") or target_name)
        target_type = item["type"]

        for ace in obj.get("Aces") or []:
            if not isinstance(ace, dict):
                continue
            principal_sid = str(ace.get("PrincipalSID") or ace.get("PrincipalID") or "")
            if principal_sid not in principal_sids:
                continue
            right_name = str(ace.get("RightName") or ace.get("Right") or "")
            dedupe = (principal_sid, target_sid, right_name, target_name)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            finding = _finding_from_ace(
                pivot_user=pivot_user,
                principal_sid=principal_sid,
                sid_to_label=sid_to_label,
                target_type=target_type,
                target_name=target_name,
                target_dn=target_dn,
                target_sid=target_sid,
                right_name=right_name,
            )
            if finding is not None:
                findings.append(finding)

    for idx, finding in enumerate(findings, start=1):
        finding.id = f"sh-acl-{idx:03d}"

    if findings:
        print_success(
            f"SharpHound ACL bridge: {len(findings)} outbound ACE(s) for pivot {pivot_user}"
        )
    else:
        print_info(f"SharpHound ACL bridge: no abuse ACEs for pivot {pivot_user}")

    return findings


def merge_acl_findings_file(
    ws_path: Path,
    new_findings: list[AclAbuseFinding],
    *,
    pivot_user: str,
    domain: str,
) -> Path:
    """Merge SharpHound findings into ``acl_findings.json`` (replace prior ``sh-acl-*``)."""
    path = ws_path / "acl_findings.json"
    existing: dict[str, Any] = {}
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {}

    kept = [
        f
        for f in existing.get("findings") or []
        if isinstance(f, dict) and not str(f.get("id", "")).startswith("sh-acl-")
    ]
    merged = kept + [f.to_dict() for f in new_findings]
    for idx, row in enumerate(merged, start=1):
        if str(row.get("id", "")).startswith("sh-acl-"):
            row["id"] = f"sh-acl-{idx:03d}"

    owned = list(existing.get("owned_users") or [])
    pivot_l = pivot_user.lower()
    if pivot_l and pivot_l not in {str(u).lower() for u in owned}:
        owned.append(pivot_user)

    payload = {
        "domain": domain or existing.get("domain") or "",
        "owned_users": owned,
        "finding_count": len(merged),
        "findings": merged,
        "errors": list(existing.get("errors") or []),
        "sharphound_pivot": pivot_user,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def sync_pivot_from_shell(session: Session, shell: Any | None) -> str:
    """Resolve pivot from shell ``whoami`` when available."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    pivot = str(session.workspace.pivot_user or "").strip()
    if shell is None or not getattr(shell, "session_connected", False):
        return pivot
    try:
        from admapper.postex.shell_client import parse_shell_username

        with shell.command_batch():
            probe = shell.run_command("whoami", timeout=20.0)
        parsed = parse_shell_username(probe)
        if parsed:
            pivot = parsed
    except Exception:
        pass
    return pivot


def apply_pivot_state(session: Session, pivot_user: str) -> None:
    """Mark shell collector as owned + active pivot (no LDAP refresh)."""
    from admapper.escalate.analyze import set_pivot_user
    from admapper.support.owned import is_valid_owned_username, normalize_username
    from admapper.stores.graph import GraphStore

    if session.workspace is None:
        raise RuntimeError("no active workspace")
    user = normalize_username(pivot_user)
    if not user or not is_valid_owned_username(user):
        return

    owned_lower = {u.lower() for u in session.workspace.owned_users}
    if user.lower() not in owned_lower:
        session.workspace.owned_users.append(user)
    set_pivot_user(session, user)

    domain = session.workspace.domain or session.workspace.name
    try:
        GraphStore(session.workspaces, session.workspace.name).mark_user_owned(domain, user)
    except Exception:
        pass
    session.persist_workspace()


def refresh_sharphound_intel(
    session: Session,
    pivot_user: str,
    *,
    quiet: bool = True,
) -> None:
    """Merge SH ACLs and refresh escalation state for *pivot_user*."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    ws_path = session.workspaces.path_for(session.workspace.name)
    domain = session.workspace.domain or session.workspace.name

    findings = extract_sharphound_acl_findings(ws_path, pivot_user, domain=domain)
    if findings:
        merge_acl_findings_file(ws_path, findings, pivot_user=pivot_user, domain=domain)
        try:
            from admapper.acl.analyze import _enrich_graph_with_acls
            from admapper.graph.build import focus_tactical_graph, load_focus_context
            from admapper.stores.graph import GraphStore

            graph_store = GraphStore(session.workspaces, session.workspace.name)
            _enrich_graph_with_acls(graph_store, domain, pivot_user, findings)
            graph = focus_tactical_graph(
                graph_store.load(),
                domain=domain,
                context=load_focus_context(ws_path),
                owned_users=list(session.workspace.owned_users),
                pivot_user=pivot_user,
            )
            graph_store.save(graph)
        except Exception as exc:
            if not quiet:
                print_warning(f"graph ACL enrich: {exc}")

    from admapper.escalate.analyze import run_escalate_analysis

    run_escalate_analysis(session, pivot_user=pivot_user, quiet=quiet)

    try:
        from admapper.graph.analyze import run_graph_analysis

        run_graph_analysis(session)
    except Exception as exc:
        if not quiet:
            print_warning(f"paths refresh: {exc}")
