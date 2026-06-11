from __future__ import annotations

from typing import Any

from admapper.core.output import print_info, print_success, print_table, print_warning
from admapper.guides.render import print_manual_exploit_table


def print_postex_detail(op: dict[str, Any]) -> None:
    oid = op.get("id")
    title = op.get("title")
    technique = op.get("technique")
    print_success(f"Post-ex opportunity {oid}: {title} ({technique})")
    rows = [
        ["target", op.get("target_host") or ""],
        ["context", op.get("context") or ""],
        ["severity", op.get("severity", "")],
        ["MITRE", op.get("mitre_id", "")],
    ]
    print_table("Opportunity", ["field", "value"], rows)
    print_info(op.get("summary", ""))
    if op.get("detail"):
        print_info(op.get("detail"))
    commands = op.get("manual_commands") or []
    if commands:
        print_manual_exploit_table(commands)
    else:
        print_warning("run: guide postex_local")
