from __future__ import annotations

from typing import Any

from admapper.guides.render import print_manual_exploit_table
from admapper.support.output import print_info, print_success, print_table, print_warning


def print_acl_detail(finding: dict[str, Any]) -> None:
    fid = finding.get("id")
    right = finding.get("right")
    target = finding.get("target_name")
    print_success(f"ACL finding {fid}: {right} → {target}")
    rows = [
        ["principal", finding.get("principal", "")],
        ["trustee", f"{finding.get('trustee_name')} ({finding.get('trustee_sid')})"],
        ["target", finding.get("target_dn", "")],
        ["type", finding.get("target_type", "")],
        ["severity", finding.get("severity", "")],
        ["MITRE", finding.get("mitre_id", "")],
    ]
    print_table("Finding", ["field", "value"], rows)
    print_info(finding.get("summary", ""))
    commands = finding.get("manual_commands") or []
    if commands:
        print_manual_exploit_table(commands)
    else:
        print_warning("run: guide acl_abuse")
