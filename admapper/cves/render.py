from __future__ import annotations

from typing import Any

from admapper.support.output import print_info, print_success, print_table, print_warning
from admapper.guides.render import print_manual_exploit_table


def print_cve_detail(finding: dict[str, Any]) -> None:
    fid = finding.get("id")
    title = finding.get("title")
    technique = finding.get("technique")
    print_success(f"CVE finding {fid}: {title} ({technique})")
    rows = [
        ["host", finding.get("target_host") or ""],
        ["CVEs", ", ".join(finding.get("cve_ids") or [])],
        ["severity", finding.get("severity", "")],
        ["confidence", finding.get("confidence", "")],
        ["MITRE", finding.get("mitre_id", "")],
        ["exploitable", str(finding.get("exploitable", False))],
    ]
    print_table("Finding", ["field", "value"], rows)
    print_info(finding.get("summary", ""))
    if finding.get("detail"):
        print_info(finding.get("detail"))
    commands = finding.get("manual_commands") or []
    if commands:
        print_manual_exploit_table(commands)
    else:
        print_warning("run: guide cves_exploit")
