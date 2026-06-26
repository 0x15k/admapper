from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from admapper.stores.graph import GraphStore
from admapper.support.output import print_info, print_success, print_warning
from admapper.creds.common import resolve_dc_fqdn
from admapper.escalate.edges import collect_edges_from_pivot, pick_next_edge, sort_edges
from admapper.escalate.render import print_escalation_state
from admapper.guides.render import print_manual_guide
from admapper.models.escalation import EscalationEdge, EscalationState

if TYPE_CHECKING:
    from admapper.support.session import Session


def resolve_pivot_user(session: Session) -> str:
    """Active pivot: explicit pivot_user, else best owned account for escalation."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    ws_path = session.workspaces.path_for(session.workspace.name)
    owned = list(session.workspace.owned_users or [])
    from admapper.escalate.pivot import pick_best_pivot

    best = pick_best_pivot(owned, ws_path=ws_path)
    explicit = session.workspace.pivot_user
    if explicit:
        # Upgrade stale machine pivot when a post-machine human is owned.
        if explicit.endswith("$") and best and not best.endswith("$"):
            if explicit.lower() != best.lower():
                return best
        return explicit
    if best:
        return best
    for username in reversed(owned):
        if username.endswith("$") or ":" in username:
            continue
        return username
    for username in reversed(owned):
        if not username.endswith("$"):
            return username
    raise ValueError("no owned users — run start_auth or escalate mark <user>")


def set_pivot_user(session: Session, username: str) -> None:
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    session.workspace.pivot_user = username
    session.persist_workspace()
    print_success(f"pivot → {username}")


def mark_user_owned(
    session: Session,
    username: str,
    *,
    refresh: bool = True,
) -> None:
    """BloodHound-style: mark owned, set pivot, refresh outbound edges."""
    from admapper.support.owned import is_valid_owned_username

    if not is_valid_owned_username(username):
        raise ValueError(f"invalid owned username (parser artifact?): {username}")
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain before escalate mark")

    owned_lower = {u.lower() for u in session.workspace.owned_users}
    if username.lower() not in owned_lower:
        session.workspace.owned_users.append(username)
        print_success(f"marked owned: {username}")

    session.workspace.pivot_user = username
    session.persist_workspace()

    GraphStore(session.workspaces, session.workspace.name).mark_user_owned(domain, username)

    if refresh:
        run_pivot_refresh(session, username)

    run_escalate_analysis(session, pivot_user=username)


def run_pivot_refresh(session: Session, pivot_user: str) -> None:
    """Re-run analysis modules relevant to the current pivot (step-by-step)."""
    print_info(f"refreshing intel for pivot {pivot_user} …")

    from admapper.support.output import print_warning

    steps = [
        ("paths", "admapper.graph.analyze", "run_graph_analysis"),
        ("acls", "admapper.acl.analyze", "run_acl_analysis"),
        ("kerberos", "admapper.kerberos.analyze", "run_kerberos_analysis"),
        ("adcs", "admapper.adcs.analyze", "run_adcs_analysis"),
        ("postex", "admapper.postex.analyze", "run_postex_analysis"),
        ("wsus", "admapper.wsus.analyze", "run_wsus_analysis"),
    ]
    for label, module_path, func_name in steps:
        try:
            import importlib

            mod = importlib.import_module(module_path)
            fn = getattr(mod, func_name)
            fn(session)
            print_success(f"  {label} OK")
        except (ValueError, RuntimeError, ImportError) as exc:
            print_warning(f"  {label}: {exc}")


def run_escalate_analysis(
    session: Session,
    *,
    pivot_user: str | None = None,
    quiet: bool = False,
) -> EscalationState:
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    from admapper.support.owned import sanitize_owned_users

    clean, removed = sanitize_owned_users(list(session.workspace.owned_users))
    if removed:
        session.workspace.owned_users = clean
        session.persist_workspace()
        if not quiet:
            print_warning(f"removed bogus owned entries: {', '.join(removed)}")

    domain = session.workspace.domain or ""
    ws_path = session.workspaces.path_for(session.workspace.name)
    pivot = pivot_user or resolve_pivot_user(session)

    from admapper.support.verbosity import print_phase

    if not quiet:
        print_phase(f"Escalation analysis — pivot: {pivot}")

    from admapper.adcs.enrich import enrich_adcs_findings_file

    enrich_adcs_findings_file(ws_path)

    # Check for shadow admins (stale adminCount)
    try:
        from admapper.stores.findings import FindingsStore
        from admapper.models.finding import Finding, FindingSeverity
        from admapper.graph.catalog import HIGH_VALUE_GROUPS

        inventory_path = ws_path / "auth_inventory.json"
        if inventory_path.is_file():
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            
            dn_to_groups = {}
            for group in inventory.get("groups", []):
                group_name = str(group.get("name") or "").lower()
                for member_dn in group.get("members") or []:
                    dn_to_groups.setdefault(member_dn.lower(), []).append(group_name)

            name_to_dn = {}
            for group in inventory.get("groups", []):
                gname = str(group.get("name") or "").lower()
                gdn = str(group.get("dn") or "").lower()
                name_to_dn[gname] = gdn

            def get_all_groups_for_dn(dn: str, visited=None) -> set[str]:
                if visited is None:
                    visited = set()
                if dn.lower() in visited:
                    return set()
                visited.add(dn.lower())
                
                direct_groups = dn_to_groups.get(dn.lower(), [])
                all_groups = set(direct_groups)
                for gname in direct_groups:
                    g_dn = name_to_dn.get(gname)
                    if g_dn:
                        all_groups.update(get_all_groups_for_dn(g_dn, visited))
                return all_groups

            shadow_admins = []
            for user in inventory.get("users", []):
                username = str(user.get("username") or "")
                user_dn = str(user.get("dn") or "")
                if not username or not user_dn:
                    continue
                if username.lower() == "krbtgt":
                    continue
                
                if user.get("admin_count") == 1:
                    user_groups = get_all_groups_for_dn(user_dn)
                    has_admin_group = any(g in HIGH_VALUE_GROUPS for g in user_groups)
                    if not has_admin_group:
                        shadow_admins.append(username)

            if shadow_admins:
                findings_store = FindingsStore(session.workspaces, session.workspace.name)
                findings_store.merge([
                    Finding(
                        key="stale_admin_count",
                        title=f"Stale adminCount 'Shadow Admins' detected ({len(shadow_admins)})",
                        severity=FindingSeverity.HIGH,
                        source="escalate",
                        detail=f"Accounts with adminCount=1 but not in any admin groups: {', '.join(shadow_admins)}",
                        mitre_id="T1078.002",
                    )
                ])
                if not quiet:
                    print_warning(f"Detected {len(shadow_admins)} shadow admin accounts with stale adminCount!")
    except Exception as exc:
        if not quiet:
            print_warning(f"Failed stale adminCount check: {exc}")

    edges = collect_edges_from_pivot(
        pivot_user=pivot,
        owned_users=list(session.workspace.owned_users),
        ws_path=ws_path,
        domain=domain,
    )
    next_edge = pick_next_edge(edges)

    history_path = ws_path / "escalate_history.json"
    history: list[dict[str, Any]] = []
    if history_path.is_file():
        history = json.loads(history_path.read_text(encoding="utf-8")).get("steps") or []

    state = EscalationState(
        pivot_user=pivot,
        owned_users=list(session.workspace.owned_users),
        edges=edges,
        next_edge=next_edge,
        history=history,
    )

    out = ws_path / "escalate.json"
    out.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    from admapper.support.verbosity import is_verbose

    if is_verbose() and not quiet:
        print_escalation_state(state)
        print_manual_guide("escalate", session=session)
    return state


def record_escalation_step(session: Session, *, action: str, detail: str = "") -> None:
    """Append to escalation history when a step completes."""
    if session.workspace is None:
        return
    ws_path = session.workspaces.path_for(session.workspace.name)
    history_path = ws_path / "escalate_history.json"
    data: dict[str, Any] = {"steps": []}
    if history_path.is_file():
        data = json.loads(history_path.read_text(encoding="utf-8"))
    data.setdefault("steps", []).append(
        {
            "timestamp": datetime.now(UTC).isoformat(),
            "pivot": session.workspace.pivot_user,
            "action": action,
            "detail": detail,
            "owned_users": list(session.workspace.owned_users),
        }
    )
    history_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def get_escalation_state(session: Session) -> dict[str, Any] | None:
    if session.workspace is None:
        return None
    path = session.workspaces.path_for(session.workspace.name) / "escalate.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def run_escalate_exec(session: Session, *, op_id: str | None = None) -> None:
    """Execute the next (or specified) escalation edge when wired."""
    from admapper.support.connectivity import TargetUnreachableError, format_unreachable_message, require_target_reachable
    from admapper.support.output import print_error
    from admapper.models.workspace import OperationMode

    if session.workspace and session.workspace.mode == OperationMode.AUTO:
        try:
            require_target_reachable(session)
        except TargetUnreachableError as exc:
            raise RuntimeError(format_unreachable_message(exc)) from exc

    state = get_escalation_state(session)
    if state is None:
        run_escalate_analysis(session)
        state = get_escalation_state(session)
    if state is None:
        raise RuntimeError("escalate analysis produced no state")

    edge = state.get("next") or {}
    if op_id:
        for candidate in state.get("edges") or []:
            if candidate.get("op_id") == op_id:
                edge = candidate
                break
        else:
            raise ValueError(f"escalation edge not found: {op_id}")

    if not edge:
        print_warning("no next escalation step")
        return

    module = str(edge.get("module") or "")
    technique = str(edge.get("technique") or "")
    finding_id = str(edge.get("op_id") or "")

    if module == "wsus" and technique == "wsus_cert_chain":
        from admapper.wsus.runner import run_wsus_cert_chain

        result = run_wsus_cert_chain(
            session,
            op_id=finding_id or "wsus-004",
            enroll=True,
        )
        if result.enroll_success or result.cert_pfx:
            record_escalation_step(session, action="wsus_cert_chain", detail=result.wsus_host)
        return

    if module == "adcs" and technique == "template_enrollment":
        from admapper.adcs.runner import run_certipy_enrollment, run_enroll_hijack

        fid = finding_id or "adcs-002"
        host = resolve_dc_fqdn(str(ws_path), domain) or f"dc01.{domain}"
        result = run_certipy_enrollment(session, finding_id=fid, dns_name=host)
        if not result.success and result.error and "no pivot credential" in result.error:
            print_info("no pivot hash — enroll via DLL-hijack task, then restart the chain")
            from admapper.postex.analyze import resolve_hijack_op_id

            result = run_enroll_hijack(
                session,
                finding_id=fid,
                dns_name=host,
                op_id=resolve_hijack_op_id(session),
            )
        if result.success:
            record_escalation_step(session, action="adcs_enroll", detail=finding_id)
        return

    if module == "postex" and technique == "dll_hijack_scheduled_task":
        from admapper.postex.analyze import resolve_hijack_op_id
        from admapper.postex.runner import run_dll_hijack
        from admapper.models.workspace import OperationMode

        record_escalation_step(
            session,
            action="dll_hijack_exec",
            detail=finding_id or resolve_hijack_op_id(session) or "auto",
        )
        auto_chain = bool(
            session.workspace and session.workspace.mode == OperationMode.AUTO
        )
        run_dll_hijack(
            session,
            op_id=finding_id or resolve_hijack_op_id(session),
            wait_seconds=300,
            auto_chain=auto_chain,
        )
        return

    print_error(f"escalate exec not wired for {module}/{technique} — use manual_commands in escalate show")
    manual = edge.get("manual_commands") or []
    for line in manual[:5]:
        print_info(str(line))
