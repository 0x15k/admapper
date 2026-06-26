from __future__ import annotations

from typing import Any

from admapper.support.output import print_info, print_success, print_table, print_warning
from admapper.guides.render import print_manual_exploit_table


def print_adcs_detail(finding: dict[str, Any]) -> None:
    fid = finding.get("id")
    esc = finding.get("esc")
    title = finding.get("title")
    print_success(f"AD CS finding {fid}: {title} ({esc})")
    rows = [
        ["template", finding.get("template") or ""],
        ["ca", finding.get("ca_name") or ""],
        ["principal", finding.get("principal") or ""],
        ["ready", "yes" if finding.get("prerequisites_met", True) else "no"],
        ["severity", finding.get("severity", "")],
        ["MITRE", finding.get("mitre_id", "")],
    ]
    print_table("Finding", ["field", "value"], rows)
    print_info(finding.get("summary", ""))
    if finding.get("detail"):
        print_info(finding.get("detail"))
    commands = finding.get("manual_commands") or []
    if commands:
        print_manual_exploit_table(commands)
    else:
        print_warning("run: guide adcs_esc")
