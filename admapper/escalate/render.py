from __future__ import annotations

from admapper.core.output import print_info, print_success, print_table, print_warning
from admapper.core.verbosity import is_verbose
from admapper.models.escalation import EscalationState


def print_escalation_state(state: EscalationState) -> None:
    if not is_verbose():
        return
    owned = ", ".join(state.owned_users) if state.owned_users else "(none)"
    print_success(f"Pivot: {state.pivot_user}")
    print_info(f"Owned: {owned}")

    if not state.edges:
        print_warning(f"no outbound edges from {state.pivot_user} — run: acls, postex, adcs")
        return

    rows = []
    for idx, edge in enumerate(state.edges[:12], start=1):
        status = "done" if edge.target_owned else ("ready" if edge.ready else "blocked")
        rows.append(
            [
                str(idx),
                edge.module,
                edge.technique,
                edge.target[:28] if edge.target else "",
                edge.severity,
                status,
            ]
        )
    print_table(
        f"Outbound from {state.pivot_user} (BloodHound-style 1-hop)",
        ["#", "module", "technique", "target", "sev", "status"],
        rows,
    )

    nxt = state.next_edge
    if nxt:
        print_success(f"NEXT → [{nxt.module}] {nxt.title}")
        if nxt.op_id:
            print_info(f"  show: {nxt.module} show {nxt.op_id}")
        for cmd in nxt.manual_commands[:2]:
            print_info(f"  {cmd}")
    else:
        print_warning("no ready next hop — mark next owned user: escalate mark <user>")
