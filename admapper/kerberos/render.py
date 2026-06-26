from __future__ import annotations

from typing import Any

from admapper.guides.render import print_manual_exploit_table
from admapper.support.output import print_info, print_success, print_table, print_warning


def print_kerberos_op_detail(op: dict[str, Any]) -> None:
    oid = op.get("id")
    title = op.get("title")
    technique = op.get("technique")
    print_success(f"Kerberos opportunity {oid}: {title} ({technique})")
    rows = [
        ["source", f"{op.get('source_object')} ({op.get('source_type')})"],
        ["target", op.get("target") or ""],
        ["severity", op.get("severity", "")],
        ["MITRE", op.get("mitre_id", "")],
        ["owned relevant", "yes" if op.get("owned_relevant") else "no"],
    ]
    print_table("Opportunity", ["field", "value"], rows)
    if op.get("targets"):
        print_table("Targets", ["spn/target"], [[t] for t in op["targets"][:10]])
    print_info(op.get("summary", ""))
    if op.get("detail"):
        print_info(op.get("detail"))
    commands = op.get("manual_commands") or []
    if commands:
        print_manual_exploit_table(commands)
    else:
        print_warning("run: guide kerberos_adv")
