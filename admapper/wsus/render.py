from __future__ import annotations

from typing import Any

from admapper.support.output import print_info, print_success, print_table, print_warning
from admapper.guides.render import print_manual_exploit_table


def print_wsus_detail(finding: dict[str, Any]) -> None:
    fid = finding.get("id")
    title = finding.get("title")
    technique = finding.get("technique")
    ready = finding.get("prerequisites_met", False)
    print_success(f"WSUS opportunity {fid}: {title} ({technique})")
    rows = [
        ["host", finding.get("target_host") or ""],
        ["context", finding.get("context") or ""],
        ["ready", "yes" if ready else "no — prerequisites pending"],
        ["severity", finding.get("severity", "")],
        ["MITRE", finding.get("mitre_id", "")],
    ]
    print_table("Opportunity", ["field", "value"], rows)
    print_info(finding.get("summary", ""))
    if finding.get("detail"):
        print_info(finding.get("detail"))

    prereqs = finding.get("prerequisites") or []
    if prereqs:
        print_table(
            "Prerequisites",
            ["key", "met", "detail"],
            [[p.get("label", p.get("key")), "yes" if p.get("met") else "no", p.get("detail", "")]
             for p in prereqs],
        )

    commands = finding.get("manual_commands") or []
    if commands and ready:
        print_manual_exploit_table(commands)
    elif commands:
        print_warning("prerequisites not fully met — commands shown for reference")
        print_manual_exploit_table(commands)
    else:
        print_warning("run: guide wsus_esc")
