from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from admapper.adcs.eku import template_profile_from_inventory


def enrich_finding_dict(finding: dict[str, Any], inventory: dict[str, Any] | None) -> dict[str, Any]:
    """Attach EKU / WSUS-chain flags from adcs_inventory.json to a finding dict."""
    template = str(finding.get("template") or "")
    if not template:
        return finding
    profile = template_profile_from_inventory(inventory, template)
    if not profile:
        return finding
    out = dict(finding)
    if profile.get("eku_labels"):
        out["eku_summary"] = ", ".join(profile["eku_labels"])
    out["cert_auth_viable"] = bool(profile.get("cert_auth_viable"))
    out["wsus_chain_step"] = bool(profile.get("wsus_chain_step"))
    if out["wsus_chain_step"]:
        principal = finding.get("principal") or "pivot user"
        out["title"] = f"{template} enrollment → WSUS chain (Server Auth only)"
        out["detail"] = (
            f"{principal} can enroll in {template} ({out.get('eku_summary', 'Server Authentication')}). "
            "No Client Authentication — use cert with WSUS spoofing toward DA, not certipy auth."
        )
        cmds = list(finding.get("manual_commands") or [])
        filtered = [c for c in cmds if "certipy auth" not in c.lower()]
        if not any("wsus" in c.lower() or "pywsus" in c.lower() for c in filtered):
            filtered.extend(
                [
                    "admapper postex run --mode enroll --op postex-010 --arch x86",
                    "python3 pywsus.py -s <wsus_host> publish ...",
                ]
            )
        out["manual_commands"] = filtered
    return out


def enrich_adcs_findings_file(ws_path: Path) -> bool:
    """Patch adcs_findings.json in-place from adcs_inventory.json (no LDAP)."""
    findings_path = ws_path / "adcs_findings.json"
    inventory_path = ws_path / "adcs_inventory.json"
    if not findings_path.is_file() or not inventory_path.is_file():
        return False
    data = json.loads(findings_path.read_text(encoding="utf-8"))
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    findings = [enrich_finding_dict(f, inventory) for f in data.get("findings") or []]
    data["findings"] = findings
    findings_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return True
