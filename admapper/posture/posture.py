"""Fase 8.8 — Security posture and misconfiguration checks.

Checks implemented:
  - SMB signing enforcement (relay relay-friendly?)
  - LAPS deployment (are admin passwords randomised?)
  - NTLMv1 acceptance (downgrade possible?)
  - LDAP signing enforcement (LDAP relay/MitM possible?)
  - Domain Admin sessions (where are DA tokens live?)

All checks are non-destructive read-only queries.
Output: security_posture.json + findings.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from admapper.stores.findings import FindingsStore
from admapper.support.output import print_info, print_success, print_table, print_warning
from admapper.support.platform import resolve_nxc, run_command
from admapper.models.credential import Credential
from admapper.models.finding import Finding, FindingSeverity

if TYPE_CHECKING:
    from admapper.support.session import Session


@dataclass
class PostureResult:
    smb_signing: bool | None = None          # True = required (good), False = not required (bad)
    laps_deployed: bool | None = None        # True = LAPS present
    laps_covered_count: int = 0             # computers with LAPS password set
    ntlmv1_accepted: bool | None = None     # True = server accepts NTLMv1 (bad)
    ldap_signing_required: bool | None = None  # True = required (good)
    da_sessions: list[dict[str, str]] = field(default_factory=list)  # active DA sessions
    stale_computers: list[dict[str, Any]] = field(default_factory=list) # stale computer accounts
    errors: list[str] = field(default_factory=list)


def check_security_posture(
    session: "Session",
    dc_ip: str,
    cred: Credential,
    domain: str,
) -> PostureResult:
    """Phase 8.8 — Run all security posture checks against the DC.

    Args:
        dc_ip: Domain controller IP address.
        cred: Valid domain credential.
        domain: Domain FQDN.

    Returns:
        PostureResult with all findings populated.
    """
    result = PostureResult()
    ws_name = session.workspace.name  # type: ignore[union-attr]
    ws_path = session.workspaces.path_for(ws_name)

    print_info("Fase 8.8 — security posture checks")

    # 1. SMB signing — already gathered by smb_enum, read from inventory
    smb_signing = _read_smb_signing(ws_path)
    if smb_signing is not None:
        result.smb_signing = smb_signing
    else:
        result.smb_signing = _check_smb_signing(dc_ip, cred, domain)

    # 2. LAPS detection via LDAP
    result.laps_deployed, result.laps_covered_count = _check_laps(dc_ip, cred, domain)

    # 3. NTLMv1 check via nxc
    result.ntlmv1_accepted = _check_ntlmv1(dc_ip, cred, domain)

    # 4. LDAP signing
    result.ldap_signing_required = _check_ldap_signing(dc_ip, cred, domain)

    # 5. DA sessions
    result.da_sessions = _check_da_sessions(ws_path, dc_ip, cred, domain)

    # 6. Stale computers
    result.stale_computers = _check_stale_computers(ws_path)

    # Print summary
    _print_posture_summary(result)

    # Persist findings
    findings_store = FindingsStore(session.workspaces, ws_name)
    _emit_findings(findings_store, result, dc_ip)

    # Save JSON
    out_path = ws_path / "security_posture.json"
    out_path.write_text(
        json.dumps(
            {
                "fetched_at": datetime.now(UTC).isoformat(),
                "dc_ip": dc_ip,
                "domain": domain,
                "smb_signing_required": result.smb_signing,
                "laps_deployed": result.laps_deployed,
                "laps_covered_computers": result.laps_covered_count,
                "ntlmv1_accepted": result.ntlmv1_accepted,
                "ldap_signing_required": result.ldap_signing_required,
                "da_sessions": result.da_sessions,
                "stale_computers": result.stale_computers,
                "errors": result.errors,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print_success("security posture saved → security_posture.json")
    return result


# ── Individual checks ──────────────────────────────────────────────────────

def _read_smb_signing(ws_path: Path) -> bool | None:
    """Read SMB signing from existing auth_inventory.json."""
    inv_path = ws_path / "auth_inventory.json"
    if not inv_path.is_file():
        return None
    try:
        data = json.loads(inv_path.read_text(encoding="utf-8"))
        val = data.get("smb_signing_required")
        if val is not None:
            return bool(val)
    except Exception:
        pass
    return None


def _check_smb_signing(dc_ip: str, cred: Credential, domain: str) -> bool | None:
    """Probe SMB signing via nxc."""
    nxc = resolve_nxc()
    if not nxc:
        return None
    try:
        cmd = [nxc, "smb", dc_ip, "-u", cred.username, "-p", cred.secret or "", "-d", domain]
        proc = run_command(cmd, timeout=20)
        output = (proc.stdout or "") + (proc.stderr or "")
        if "signing:True" in output or "SMB signing required" in output:
            return True
        if "signing:False" in output:
            return False
    except Exception:
        pass
    return None


def _check_laps(dc_ip: str, cred: Credential, domain: str) -> tuple[bool | None, int]:
    """Detect LAPS via LDAP — check for ms-Mcs-AdmPwd attribute on computer objects."""
    try:
        from ldap3 import Server, Connection, SUBTREE, ALL
        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
        srv = Server(dc_ip, get_info=ALL)
        conn = Connection(
            srv,
            user=f"{domain}\\{cred.username}",
            password=cred.secret or "",
            auto_bind=True,
        )
        # Check if LAPS schema attribute exists
        schema_ok = False
        try:
            conn.search(
                "CN=Schema,CN=Configuration," + base_dn,
                "(ldapDisplayName=ms-Mcs-AdmPwd)",
                SUBTREE,
                attributes=["ldapDisplayName"],
            )
            schema_ok = bool(conn.entries)
        except Exception:
            # Try new Windows LAPS attribute
            try:
                conn.search(
                    "CN=Schema,CN=Configuration," + base_dn,
                    "(ldapDisplayName=msLAPS-Password)",
                    SUBTREE,
                    attributes=["ldapDisplayName"],
                )
                schema_ok = bool(conn.entries)
            except Exception:
                pass

        covered = 0
        if schema_ok:
            # Count computers with LAPS password attribute set
            try:
                conn.search(
                    base_dn,
                    "(&(objectClass=computer)(ms-Mcs-AdmPwdExpirationTime=*))",
                    SUBTREE,
                    attributes=["sAMAccountName"],
                )
                covered = len(conn.entries)
            except Exception:
                try:
                    conn.search(
                        base_dn,
                        "(&(objectClass=computer)(msLAPS-Password=*))",
                        SUBTREE,
                        attributes=["sAMAccountName"],
                    )
                    covered = len(conn.entries)
                except Exception:
                    covered = 0

        conn.unbind()
        return schema_ok, covered
    except Exception:
        pass
    return None, 0


def _check_ntlmv1(dc_ip: str, cred: Credential, domain: str) -> bool | None:
    """Check if the DC accepts NTLMv1 via nxc --ntlmv1 flag."""
    nxc = resolve_nxc()
    if not nxc:
        return None
    try:
        cmd = [
            nxc, "smb", dc_ip,
            "-u", cred.username,
            "-p", cred.secret or "",
            "-d", domain,
            "--ntlmv1",
        ]
        proc = run_command(cmd, timeout=20)
        output = (proc.stdout or "") + (proc.stderr or "")
        if "ntlmv1" in output.lower() and "accepted" in output.lower():
            return True
        if "does not support ntlmv1" in output.lower():
            return False
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def _check_ldap_signing(dc_ip: str, cred: Credential, domain: str) -> bool | None:
    """Check LDAP signing via nxc ldap-checker module or direct bind without signing."""
    nxc = resolve_nxc()
    if not nxc:
        return _check_ldap_signing_native(dc_ip, cred, domain)
    try:
        cmd = [
            nxc, "ldap", dc_ip,
            "-u", cred.username,
            "-p", cred.secret or "",
            "-d", domain,
            "-M", "ldap-checker",
        ]
        proc = run_command(cmd, timeout=30)
        output = (proc.stdout or "") + (proc.stderr or "")
        if "ldap signing is required" in output.lower():
            return True
        if "ldap signing is not required" in output.lower():
            return False
    except Exception:
        pass
    return _check_ldap_signing_native(dc_ip, cred, domain)


def _check_ldap_signing_native(dc_ip: str, cred: Credential, domain: str) -> bool | None:
    """Try LDAP bind without signing — if it succeeds, signing is not required."""
    try:
        from ldap3 import Server, Connection, ALL, SIMPLE
        srv = Server(dc_ip, get_info=ALL)
        conn = Connection(
            srv,
            user=f"{domain}\\{cred.username}",
            password=cred.secret or "",
            authentication=SIMPLE,
        )
        if conn.bind():
            conn.unbind()
            return False  # binding without signing succeeded → not required
    except Exception:
        pass
    return None


def _check_da_sessions(
    ws_path: Path,
    dc_ip: str,
    cred: Credential,
    domain: str,
) -> list[dict[str, str]]:
    """Identify active Domain Admin sessions on domain computers.

    Uses nxc --sessions on DCs, or reads graph/inventory for active sessions.
    """
    sessions: list[dict[str, str]] = []

    # Try to read DA members from inventory
    da_members = _get_da_members(ws_path)
    if not da_members:
        return sessions

    # Try nxc --sessions on the DC
    nxc = resolve_nxc()
    if not nxc:
        return sessions
    try:
        cmd = [
            nxc, "smb", dc_ip,
            "-u", cred.username,
            "-p", cred.secret or "",
            "-d", domain,
            "--sessions",
        ]
        proc = run_command(cmd, timeout=30)
        output = proc.stdout or ""
        for line in output.splitlines():
            for da_user in da_members:
                if da_user.lower() in line.lower():
                    sessions.append({"user": da_user, "host": dc_ip, "raw": line.strip()})
                    break
    except Exception:
        pass

    return sessions[:20]


def _get_da_members(ws_path: Path) -> list[str]:
    """Extract Domain Admins group members from auth_inventory.json."""
    inv_path = ws_path / "auth_inventory.json"
    if not inv_path.is_file():
        return []
    try:
        data = json.loads(inv_path.read_text(encoding="utf-8"))
        for group in data.get("groups") or []:
            if str(group.get("name", "")).lower() in ("domain admins", "domain administrators"):
                members = group.get("members") or []
                return [
                    m.split(",")[0].removeprefix("CN=")
                    for m in members
                    if m
                ]
    except Exception:
        pass
    return []


def _check_stale_computers(ws_path: Path) -> list[dict[str, Any]]:
    """Identify stale computer accounts with passwords older than 45 days."""
    inv_path = ws_path / "auth_inventory.json"
    stale: list[dict[str, Any]] = []
    if not inv_path.is_file():
        return stale
    try:
        data = json.loads(inv_path.read_text(encoding="utf-8"))
        computers = data.get("computers") or []
        import time
        interval_45_days = 45 * 86400 * 10000000
        now_filetime = int(time.time() * 10000000) + 116444736000000000
        for comp in computers:
            pwd_last_set = comp.get("pwd_last_set")
            if pwd_last_set is not None:
                try:
                    pwd_last_set = int(pwd_last_set)
                except (ValueError, TypeError):
                    continue
                if pwd_last_set == 0:
                    stale.append({
                        "name": comp.get("name"),
                        "dn": comp.get("dn"),
                        "dns_host": comp.get("dns_host"),
                        "pwd_last_set": 0,
                        "reason": "Password never changed"
                    })
                elif (now_filetime - pwd_last_set) > interval_45_days:
                    stale.append({
                        "name": comp.get("name"),
                        "dn": comp.get("dn"),
                        "dns_host": comp.get("dns_host"),
                        "pwd_last_set": pwd_last_set,
                        "reason": "Password older than 45 days"
                    })
    except Exception:
        pass
    return stale


# ── Output ─────────────────────────────────────────────────────────────────

def _print_posture_summary(result: PostureResult) -> None:
    rows: list[list[str]] = []
    nxc_missing = not bool(resolve_nxc())

    def _status(val: bool | None, good_if_true: bool = True) -> str:
        if val is None:
            return "[dim]unknown[/dim]"
        ok = val if good_if_true else not val
        return "[bold green]✅ ok[/bold green]" if ok else "[bold red]⚠️  RISK[/bold red]"

    # SMB signing check (runs natively)
    smb_detail = ""
    if result.smb_signing is None:
        smb_detail = "check failed/timed out"
    elif not result.smb_signing:
        smb_detail = "relay-friendly — NTLM relay viable"
    rows.append(["SMB signing required", _status(result.smb_signing), smb_detail])

    # LAPS check (runs natively)
    laps_detail = ""
    if result.laps_deployed is None:
        laps_detail = "local admin reuse risk (read/schema search failed)"
    elif result.laps_deployed:
        laps_detail = f"{result.laps_covered_count} computer(s) covered"
    else:
        laps_detail = "local admin reuse risk"
    rows.append(["LAPS deployed", _status(result.laps_deployed), laps_detail])

    # NTLMv1 check (depends on NetExec/nxc)
    ntlm_detail = ""
    if result.ntlmv1_accepted is None:
        ntlm_detail = "skipped (NetExec/nxc missing)" if nxc_missing else "check failed/timed out"
    elif result.ntlmv1_accepted:
        ntlm_detail = "relay to RC4 / downgrade"
    rows.append(["NTLMv1 accepted", _status(result.ntlmv1_accepted, good_if_true=False), ntlm_detail])

    # LDAP signing check (depends on NetExec/nxc, falls back to native bind)
    ldap_detail = ""
    if result.ldap_signing_required is None:
        ldap_detail = "skipped (NetExec/nxc missing)" if nxc_missing else "check failed/timed out"
    elif not result.ldap_signing_required:
        ldap_detail = "LDAP relay / MitM viable"
    rows.append(["LDAP signing required", _status(result.ldap_signing_required), ldap_detail])

    rows.append(["DA sessions detected", str(len(result.da_sessions)),
                 ", ".join(s["user"] for s in result.da_sessions[:3]) if result.da_sessions else "none"])
    rows.append(["Stale computers detected", str(len(result.stale_computers)),
                 ", ".join(str(c["name"]) for c in result.stale_computers[:3]) if result.stale_computers else "none"])

    print_table("Security posture", ["check", "status", "detail"], rows)


def _emit_findings(
    findings_store: FindingsStore,
    result: PostureResult,
    dc_ip: str,
) -> None:
    findings: list[Finding] = []

    if result.smb_signing is False:
        findings.append(
            Finding(
                key="smb_signing_not_required",
                title="SMB signing not required — NTLM relay viable",
                severity=FindingSeverity.HIGH,
                source="posture",
                detail=f"DC {dc_ip} does not require SMB signing",
                mitre_id="T1557.001",
            )
        )
    if result.laps_deployed is False:
        findings.append(
            Finding(
                key="laps_not_deployed",
                title="LAPS not deployed — local admin password reuse risk",
                severity=FindingSeverity.MEDIUM,
                source="posture",
                detail="ms-Mcs-AdmPwd schema attribute absent",
                mitre_id="T1078.002",
            )
        )
    if result.ntlmv1_accepted is True:
        findings.append(
            Finding(
                key="ntlmv1_accepted",
                title="NTLMv1 accepted — downgrade + relay attack possible",
                severity=FindingSeverity.HIGH,
                source="posture",
                detail="Server accepts NTLMv1 authentication",
                mitre_id="T1557.001",
            )
        )
    if result.ldap_signing_required is False:
        findings.append(
            Finding(
                key="ldap_signing_not_required",
                title="LDAP signing not required — LDAP relay viable",
                severity=FindingSeverity.HIGH,
                source="posture",
                detail="Anonymous LDAP bind or unsigned bind accepted",
                mitre_id="T1557.001",
            )
        )
    if result.da_sessions:
        findings.append(
            Finding(
                key="da_sessions_detected",
                title=f"Active Domain Admin sessions ({len(result.da_sessions)})",
                severity=FindingSeverity.HIGH,
                source="posture",
                detail=", ".join(s["user"] for s in result.da_sessions[:5]),
                mitre_id="T1078.002",
            )
        )
    if result.stale_computers:
        findings.append(
            Finding(
                key="stale_computers_detected",
                title=f"Stale computer accounts ({len(result.stale_computers)}) — potential low-detection pivot targets",
                severity=FindingSeverity.MEDIUM,
                source="posture",
                detail=", ".join(str(c.get("name")) for c in result.stale_computers[:10]),
                mitre_id="T1078.002",
            )
        )

    if findings:
        findings_store.merge(findings)
