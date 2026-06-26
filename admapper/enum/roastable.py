"""Phase 3 — Roastable account detection (AS-REP + Kerberoast targets).

Identifies targets without requesting any ticket:
  - AS-REP roastable: DONT_REQ_PREAUTH (UAC 0x400000) via LDAP or SAMR
  - Kerberoastable: accounts with SPN (excl. krbtgt + machine accounts)

Prerequisite: Phase 2 (users.json / auth_inventory.json available).
MITRE: T1558.004 (AS-REP), T1558.003 (Kerberoast)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.stores.findings import FindingsStore
from admapper.support.output import print_info, print_success, print_table, print_warning
from admapper.models.finding import Finding, FindingSeverity
from admapper.models.user import UAC_DONT_REQ_PREAUTH, UserRecord

if TYPE_CHECKING:
    from admapper.support.session import Session


@dataclass
class RoastableReport:
    """Summary of discovered roastable targets."""

    asrep_targets: list[UserRecord] = field(default_factory=list)
    kerberoast_targets: list[UserRecord] = field(default_factory=list)
    password_not_required: list[UserRecord] = field(default_factory=list)
    source: str = "unknown"


def detect_roastable_targets(session: Session) -> RoastableReport:
    """Phase 3 — Detect AS-REP and Kerberoast targets from existing inventory.

    Reads users.json / auth_inventory.json and surfaces roastable accounts
    *before* any ticket is requested. Emits findings and prints summary.

    Returns:
        RoastableReport with categorised target lists.
    """
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    ws_name = session.workspace.name
    ws_path = session.workspaces.path_for(ws_name)

    report = RoastableReport()
    users = _load_users(ws_path)

    if not users:
        print_warning(
            "no user inventory found — run 'enum users' first (Phase 2)"
        )
        return report

    human_users = [u for u in users if not u.is_machine_account and u.enabled]

    # AS-REP roastable: DONT_REQ_PREAUTH flag
    report.asrep_targets = [u for u in human_users if u.asrep_roastable]

    # Kerberoastable: SPN present (excl. krbtgt)
    report.kerberoast_targets = [
        u for u in human_users
        if u.kerberoastable and u.username.lower() != "krbtgt"
    ]

    # Password not required (low-hanging fruit)
    report.password_not_required = [
        u for u in human_users if u.password_not_required
    ]

    # SAMR fallback: check UAC directly for users where asrep_roastable may be
    # unset because SAMR doesn't expose UAC in detail — re-evaluate from uac field
    for u in human_users:
        if u.uac is not None and bool(u.uac & UAC_DONT_REQ_PREAUTH):
            if u not in report.asrep_targets:
                report.asrep_targets.append(u)
                u.asrep_roastable = True  # backfill flag

    report.source = _detect_source(ws_path)

    # Display
    _print_report(report)

    # Write dedicated output file
    out_path = ws_path / "roastable_targets.json"
    out_path.write_text(
        json.dumps(
            {
                "source": report.source,
                "asrep_targets": [u.username for u in report.asrep_targets],
                "kerberoast_targets": [u.username for u in report.kerberoast_targets],
                "password_not_required": [u.username for u in report.password_not_required],
                "asrep_count": len(report.asrep_targets),
                "kerberoast_count": len(report.kerberoast_targets),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # Persist findings
    findings_store = FindingsStore(session.workspaces, ws_name)
    findings: list[Finding] = []
    if report.asrep_targets:
        findings.append(
            Finding(
                key="asrep_roastable_detected",
                title=f"AS-REP roastable accounts detected ({len(report.asrep_targets)})",
                severity=FindingSeverity.MEDIUM,
                source="detect_roastables",
                detail=", ".join(u.username for u in report.asrep_targets[:10]),
                mitre_id="T1558.004",
            )
        )
    if report.kerberoast_targets:
        findings.append(
            Finding(
                key="kerberoastable_detected",
                title=f"Kerberoastable accounts detected ({len(report.kerberoast_targets)})",
                severity=FindingSeverity.MEDIUM,
                source="detect_roastables",
                detail=", ".join(u.username for u in report.kerberoast_targets[:10]),
                mitre_id="T1558.003",
            )
        )
    if report.password_not_required:
        findings.append(
            Finding(
                key="password_not_required",
                title=f"Accounts with PASSWD_NOTREQD ({len(report.password_not_required)})",
                severity=FindingSeverity.HIGH,
                source="detect_roastables",
                detail=", ".join(u.username for u in report.password_not_required[:10]),
                mitre_id="T1078",
            )
        )
    if findings:
        findings_store.merge(findings)

    return report


def _load_users(ws_path: Path) -> list[UserRecord]:
    """Load users from auth_inventory.json (preferred) or users.json."""
    # Prefer auth_inventory (richer UAC data)
    inv_path = ws_path / "auth_inventory.json"
    if inv_path.is_file():
        try:
            data = json.loads(inv_path.read_text(encoding="utf-8"))
            raw_users = data.get("users") or []
            return [UserRecord.from_dict(u) for u in raw_users]
        except Exception:
            pass

    # Fallback to users.json
    users_path = ws_path / "users.json"
    if users_path.is_file():
        try:
            data = json.loads(users_path.read_text(encoding="utf-8"))
            raw_users = data.get("users") or data if isinstance(data, list) else []
            if isinstance(data, dict):
                raw_users = data.get("users", [])
            return [UserRecord.from_dict(u) for u in raw_users]
        except Exception:
            pass

    return []


def _detect_source(ws_path: Path) -> str:
    inv_path = ws_path / "auth_inventory.json"
    users_path = ws_path / "users.json"
    if inv_path.is_file():
        return "auth_inventory"
    if users_path.is_file():
        return "users"
    return "unknown"


def _print_report(report: RoastableReport) -> None:
    total = len(report.asrep_targets) + len(report.kerberoast_targets)

    if not total and not report.password_not_required:
        print_info("no roastable targets detected in current inventory")
        return

    print_info(
        f"Fase 3 — roastable target detection: "
        f"{len(report.asrep_targets)} AS-REP, "
        f"{len(report.kerberoast_targets)} Kerberoast"
    )

    rows: list[list[str]] = []
    for u in report.asrep_targets:
        spn_flag = "yes" if u.kerberoastable else ""
        rows.append([u.username, "AS-REP (DONT_REQ_PREAUTH)", spn_flag, "T1558.004"])
    for u in report.kerberoast_targets:
        if u.asrep_roastable:
            continue  # already listed above
        rows.append([u.username, "Kerberoast (SPN)", f"{len(u.spns)} SPN(s)", "T1558.003"])
    for u in report.password_not_required:
        rows.append([u.username, "PASSWD_NOTREQD", "", "T1078"])

    if rows:
        print_table(
            "Roastable targets (pre-attack detection)",
            ["user", "type", "detail", "MITRE"],
            rows,
        )

    if report.asrep_targets:
        print_success(
            f"AS-REP targets → run 'asreproast' to harvest hashes: "
            + ", ".join(u.username for u in report.asrep_targets[:5])
        )
    if report.kerberoast_targets:
        print_success(
            f"Kerberoast targets → run 'kerberoast': "
            + ", ".join(u.username for u in report.kerberoast_targets[:5])
        )
