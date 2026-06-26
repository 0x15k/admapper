from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from admapper import __version__
from admapper.report.collect import CollectedReport, collect_workspace_report
from admapper.report.summary import build_summary

# Generic heuristics that distract from verified attack chains.
_NOISE_TECHNIQUES = frozenset(
    {
        "zerologon",
        "nopac",
        "printnightmare",
        "passnotreq",
        "golden_cert",
    }
)

_ACTIONABLE_CATEGORIES = frozenset(
    {"acl", "adcs", "kerberos", "postex", "quick_wins", "recon"},
)


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _priority_findings(collected: CollectedReport) -> list[Any]:
    """Return high-value findings, suppressing generic CVE noise."""
    items = []
    for item in collected.items:
        title_lower = item.title.lower()
        technique = (item.technique or "").lower()
        if any(noise in title_lower or noise in technique for noise in _NOISE_TECHNIQUES):
            continue
        if item.category == "cve" and item.severity in {"critical", "high"}:
            continue
        if item.severity in {"critical", "high"} and item.category in _ACTIONABLE_CATEGORIES:
            items.append(item)
    # Dedupe by title
    seen: set[str] = set()
    unique = []
    for item in items:
        key = item.title.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique[:12]


def build_engagement_summary(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
) -> str:
    """Human-first engagement narrative — start here."""
    collected = collect_workspace_report(ws_path)
    summary = build_summary(collected.items)
    exploit_log = _load_json(ws_path / "exploit_log.json")
    loot_manifest = _load_json(ws_path / "loot_manifest.json")
    acl_data = _load_json(ws_path / "acl_findings.json")

    lines = [
        "ADMapper Engagement Summary",
        "=" * 60,
        f"Workspace: {workspace}",
        f"Domain:    {domain or '(not set)'}",
        f"Generated: {datetime.now(UTC).isoformat()}",
        f"Version:   {__version__}",
        "",
        "START HERE — this file replaces reading 20+ JSON artefacts.",
        "",
    ]

    # What ADMapper did (automated)
    lines.append("What ADMapper did")
    lines.append("-" * 60)
    if exploit_log and exploit_log.get("steps"):
        for step in exploit_log["steps"]:
            gained = step.get("gained") or []
            gained_part = f" → gained {', '.join(gained)}" if gained else ""
            lines.append(
                f"  [{step.get('status', '?').upper():7}] {step.get('phase')}: "
                f"{step.get('detail', '')}{gained_part}"
            )
    else:
        lines.append("  Run: admapper run -H <ip> -u <user> -p '<pass>' --full")
        lines.append("  (includes auto-exploit chain after enumeration)")

    if loot_manifest:
        lines.append("")
        lines.append(
            f"  Share loot: {loot_manifest.get('file_count', 0)} files from "
            f"{', '.join(loot_manifest.get('shares_looted') or []) or 'none'}"
        )
        parsed = loot_manifest.get("parsed_credentials") or []
        for cred in parsed[:5]:
            lines.append(
                f"    cred: {cred.get('username')} from {cred.get('source_file')} "
                f"({cred.get('confidence')})"
            )

    lines.append("")
    lines.append("Owned principals")
    lines.append("-" * 60)
    owners = owned_users or exploit_log.get("owned_users") if exploit_log else owned_users
    if owners:
        for user in owners:
            lines.append(f"  • {user}")
    else:
        lines.append("  (none yet — add creds and run start_auth)")

    inv = _load_json(ws_path / "auth_inventory.json")
    if inv:
        protected = []
        for group in inv.get("groups") or []:
            if str(group.get("name", "")).lower() == "protected users":
                for member_dn in group.get("members") or []:
                    if "CN=" in member_dn:
                        protected.append(member_dn.split(",")[0].replace("CN=", ""))
        if protected:
            lines.append("")
            lines.append("Protected Users (Kerberos only — NTLM blocked)")
            lines.append("-" * 60)
            for account in protected:
                lines.append(f"  • {account}")
            dc = exploit_log.get("dc_ip") if exploit_log else None
            if dc:
                lines.append(f"  macOS: sudo sntp -sS {dc}")
                lines.append(f"  Linux: sudo ntpdate {dc}  (Kali: sudo ntpsec-ntpdate {dc})")
            lines.append("  Alt: brew install libfaketime + --clock-skew '+7h'")
            domain = (exploit_log or {}).get("domain") or ""
            if domain and protected:
                lines.append(
                    f"  Kerberos WinRM: evil-winrm -i <dc_fqdn> -u <protected_user> -p '<pass>' -r {domain}"
                )

    # Next actions
    lines.append("")
    lines.append("Next actions (priority order)")
    lines.append("-" * 60)

    next_actions: list[str] = []
    if exploit_log:
        for entry in exploit_log.get("new_hashes") or []:
            account = entry.get("account", "")
            nthash = entry.get("nthash", "")
            if account and nthash:
                user = account if account.endswith("$") else f"{account}$"
                dc = exploit_log.get("dc_ip") or "<DC_IP>"
                next_actions.append(
                    f"WinRM shell: nxc winrm {dc} -u '{user}' -H {nthash} -d {domain or 'DOMAIN'}"
                )
                next_actions.append(f"evil-winrm -i {dc} -u '{user}' -H {nthash}")

    cred_data = _load_json(ws_path / "credentials.json")
    if cred_data and domain:
        dc = (exploit_log or {}).get("dc_ip") or "<DC_IP>"
        for cred in cred_data.get("credentials") or []:
            if str(cred.get("type")) != "password":
                continue
            if str(cred.get("status")) != "valid":
                continue
            username = str(cred.get("username") or "")
            secret = str(cred.get("secret") or "")
            if not username or not secret:
                continue
            if username.startswith("svc_"):
                next_actions.append(
                    f"Kerberos WinRM: evil-winrm -i {domain} -u '{username}' -p '{secret}' -r {domain}"
                )

    if acl_data:
        for finding in acl_data.get("findings") or []:
            right = finding.get("right", "")
            target = finding.get("target_name", "")
            fid = finding.get("id", "")
            if right in {"genericwrite", "readgmsapassword"} and "msa" in target.lower():
                next_actions.append(f"gMSA abuse pending — run: exploit (or acls show {fid})")

    priority = _priority_findings(collected)
    for item in priority[:5]:
        if item.item_id:
            cmd_hint = {
                "adcs": f"adcs show {item.item_id}",
                "kerberos": f"kerberos show {item.item_id}",
                "postex": f"postex show {item.item_id}",
                "acl": f"acls show {item.item_id}",
            }.get(item.category, f"guide {item.technique or item.category}")
            next_actions.append(f"[{item.severity}] {item.title} — {cmd_hint}")

    if not next_actions:
        next_actions.append("No automated next step — review evidence_report.txt appendix")
    for idx, action in enumerate(dict.fromkeys(next_actions), start=1):
        lines.append(f"  {idx}. {action}")

    # Key findings (filtered)
    lines.append("")
    lines.append("Key findings (verified / actionable)")
    lines.append("-" * 60)
    if priority:
        for item in priority:
            host_part = f" @ {item.host}" if item.host else ""
            lines.append(f"  [{item.severity}] {item.title}{host_part}")
            if item.detail:
                lines.append(f"      {item.detail[:100]}")
    else:
        lines.append("  (run analysis phases first)")

    # Noise bucket
    noise_count = summary["total_items"] - len(priority)
    if noise_count > 0:
        lines.append("")
        lines.append(f"Deferred candidates ({noise_count} items)")
        lines.append("-" * 60)
        lines.append("  Generic CVE/delegation/coercion candidates are in evidence_report.txt")
        lines.append("  (ZeroLogon, noPac, PrintNightmare, Guest, Golden Cert, etc.)")
        lines.append("  Treat as unverified until confirmed manually.")

    # File map
    lines.append("")
    lines.append("Files (read order)")
    lines.append("-" * 60)
    file_map = [
        ("engagement_summary.txt", "this file — narrative + next steps"),
        ("exploit_log.json", "automated exploit chain log"),
        ("loot/", "downloaded share files"),
        ("loot_manifest.json", "loot metadata + parsed creds"),
        ("acl_findings.json", "ACL abuse opportunities"),
        ("evidence_report.txt", "full appendix (all findings)"),
    ]
    for fname, desc in file_map:
        marker = "✓" if (ws_path / fname.split("/")[0]).exists() else " "
        lines.append(f"  [{marker}] {fname:<28} {desc}")

    lines.append("")
    return "\n".join(lines) + "\n"


def write_engagement_summary(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path
