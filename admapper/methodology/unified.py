"""
Canonical AD pentest phase model — merges the best of:

- **CRTP** (Altered Security): assumed-breach AD chain, enum → priv esc → dominance
- **CRTE**: enterprise depth (trusts, AD CS, hardening bypass) as sub-tracks
- **CRTO** (Zero-Point): operator loop recon → pivot → execute → repeat
- **MITRE ATT&CK**: tactic/technique tags per phase (not the primary spine)

Dashboard exposes a shortened OPS_PHASES view; CLI/reporting use UNIFIED_PHASES (P1–P12).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from admapper.report.engagement import _load_json

PhaseStatus = Literal["done", "active", "locked", "skip"]

ENGAGEMENT_FRAMEWORK = (
    "Cadena AD unificada — CRTP (núcleo) · CRTE (avanzado) · CRTO (bucle operador) · MITRE (etiquetas)"
)


@dataclass(frozen=True)
class PhaseDef:
    id: str
    order: int
    name: str
    summary: str
    mitre_tactics: tuple[str, ...]
    crtp: str
    crte: str
    crto: str
    artifact: str
    cli_hint: str


UNIFIED_PHASES: tuple[PhaseDef, ...] = (
    PhaseDef(
        "p01",
        1,
        "Scope",
        "Workspace, target DC, reloj Kerberos, /etc/hosts",
        (),
        "—",
        "—",
        "Engagement planning",
        "state.json",
        "set workspace · sync-dc",
    ),
    PhaseDef(
        "p02",
        2,
        "Unauth discovery",
        "Dominio, DC, puertos, LDAP/SMB/Kerberos sin creds",
        ("Reconnaissance",),
        "Pre-foothold / perimeter",
        "—",
        "External + host recon (parcial)",
        "unauth_scan.json",
        "admapper scan -H <DC>",
    ),
    PhaseDef(
        "p03",
        3,
        "Identity surface",
        "Usuarios, SPNs, AS-REP roastable, política de bloqueo",
        ("Reconnaissance", "Discovery"),
        "Domain enumeration (sin cred)",
        "Enum profundo pre-auth",
        "Domain recon (pre-access)",
        "users.json · lockout_policy.json",
        "enum users",
    ),
    PhaseDef(
        "p04",
        4,
        "Credential access",
        "AS-REP, Kerberoast, spray, GPP, loot SMB",
        ("Credential Access",),
        "Kerberoast / spray / AS-REP",
        "Timeroast, GPP avanzado",
        "Credential theft",
        "loot_manifest.json · roast hashes",
        "asreproast · kerberoast · spray",
    ),
    PhaseDef(
        "p05",
        5,
        "Foothold",
        "Primera credencial válida y owned inicial",
        ("Initial Access",),
        "Assumed breach",
        "—",
        "Initial compromise (valid accounts)",
        "credentials.json (valid)",
        "admapper run -u … -p …",
    ),
    PhaseDef(
        "p06",
        6,
        "Domain enumeration",
        "LDAP/SMB autenticado, trusts, delegaciones, BloodHound",
        ("Discovery",),
        "Módulo I — domain enum",
        "Trust mapping, hybrid hints",
        "Domain reconnaissance",
        "auth_inventory.json",
        "start_auth",
    ),
    PhaseDef(
        "p07",
        7,
        "Attack-path planning",
        "Grafo, paths a DA/EA, quick wins, siguiente hop",
        ("Discovery",),
        "BloodHound / ACL mapping",
        "Cross-forest pathing",
        "Plan next hop (CRTO loop)",
        "graph.json · escalate edges",
        "paths · analyst",
    ),
    PhaseDef(
        "p08",
        8,
        "Privilege escalation",
        "ACL abuse, Kerberos adv, AD CS, CVEs en dominio",
        ("Privilege Escalation",),
        "Módulo II — domain priv esc",
        "Módulos I–III enterprise",
        "Escalate on domain",
        "acl_findings.json",
        "acls · kerberos · adcs · exploit",
    ),
    PhaseDef(
        "p09",
        9,
        "Coercion & relay",
        "PetitPotam, PrinterBug, NTLM relay hacia AD CS / LDAP",
        ("Credential Access", "Lateral Movement"),
        "—",
        "Coercion chains",
        "Relay stage",
        "coerce findings",
        "coerce",
    ),
    PhaseDef(
        "p10",
        10,
        "Lateral movement",
        "WinRM, PtH/PtT, MSSQL, post-ex remoto, AdminTo",
        ("Lateral Movement",),
        "Módulo II — lateral",
        "JEA / LAPS bypass",
        "Lateral movement",
        "postex_scan.json · winrm",
        "postex · winrm · mssql",
    ),
    PhaseDef(
        "p11",
        11,
        "Domain dominance",
        "DCSync, Golden/Silver ticket, Golden cert, trusts",
        ("Credential Access", "Persistence"),
        "Módulo III — dominance",
        "Cross-forest / EA",
        "Domain dominance",
        "exploit_log.json (dcsync)",
        "postex · manual DCSync/GT",
    ),
    PhaseDef(
        "p12",
        12,
        "Reporting",
        "Mapa engagement, MITRE Navigator, informe HTML",
        (),
        "—",
        "—",
        "Post-engagement wrap-up",
        "engagement_report.html",
        "export · brief",
    ),
)


@dataclass(frozen=True)
class PhaseDef:
    """Shortened bar for the dashboard UI (learner-friendly)."""

    id: str
    code: str
    title: str
    tech: str
    unified_ids: tuple[str, ...]
    action: str
    button: str
    detail: str


OPS_PHASES: tuple[PhaseDef, ...] = (
    PhaseDef(
        "g02",
        "RECON",
        "Perímetro",
        "DNS · LDAP · SMB · Kerberos",
        ("p02",),
        "scan",
        "ESCANEAR",
        "admapper scan -H <DC>",
    ),
    PhaseDef(
        "g03",
        "IDENT",
        "Superficie de identidades",
        "Usuarios · SPN · AS-REP · lockout",
        ("p03",),
        "brief",
        "ENUM USUARIOS",
        "enum users (tras scan)",
    ),
    PhaseDef(
        "g04",
        "CREDS",
        "Acceso a credenciales",
        "Roast · spray · loot · GPP",
        ("p04",),
        "brief",
        "VECTORES CREDS",
        "asreproast · kerberoast · spray",
    ),
    PhaseDef(
        "g05",
        "FOOTHOLD",
        "Foothold",
        "LDAP · SMB · Kerberos TGT",
        ("p05",),
        "run",
        "AUTENTICAR",
        "admapper run -u … -p …",
    ),
    PhaseDef(
        "g06",
        "ENUM",
        "Enum de dominio",
        "LDAP · SMB · BloodHound",
        ("p06",),
        "run",
        "ENUMERAR",
        "start_auth",
    ),
    PhaseDef(
        "g07",
        "PATHS",
        "Rutas de ataque",
        "Grafo · paths · ACL map",
        ("p07",),
        "acls",
        "MAPEAR RUTAS",
        "paths · acls",
    ),
    PhaseDef(
        "g08",
        "PRIVESC",
        "Escalada de privilegios",
        "ACL · Kerberos · AD CS",
        ("p08",),
        "exploit",
        "ESCALAR",
        "admapper exploit",
    ),
    PhaseDef(
        "g09",
        "MOVE",
        "Lateral & coerción",
        "WinRM · relay · MSSQL",
        ("p09", "p10"),
        "brief",
        "LATERAL",
        "postex · coerce",
    ),
    PhaseDef(
        "g11",
        "DOMINATE",
        "Dominio",
        "DCSync · Golden · persistencia",
        ("p11",),
        "brief",
        "DOMINIO",
        "postex / DCSync manual",
    ),
)


def _st(done: bool, pending: bool) -> PhaseStatus:
    if done:
        return "done"
    if pending:
        return "active"
    return "locked"


def phase_status_from_workspace(ws_path: Path) -> dict[str, PhaseStatus]:
    """Map unified phase id → status from workspace artifacts."""
    ws_path = Path(ws_path)
    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    creds = (_load_json(ws_path / "credentials.json") or {}).get("credentials") or []
    valid = [c for c in creds if str(c.get("status")) == "valid"]
    users = _load_json(ws_path / "users.json") or {}
    inv = _load_json(ws_path / "auth_inventory.json") or {}
    loot = _load_json(ws_path / "loot_manifest.json") or {}
    acl_n = len((_load_json(ws_path / "acl_findings.json") or {}).get("findings") or [])
    exploit = _load_json(ws_path / "exploit_log.json") or {}
    postex = len((_load_json(ws_path / "postex_scan.json") or {}).get("findings") or [])
    coerce_n = len((_load_json(ws_path / "coerce_findings.json") or {}).get("findings") or [])
    state = _load_json(ws_path / "state.json") or {}
    report = (ws_path / "engagement_report.html").is_file()

    has_scan = bool(unauth.get("hosts"))
    has_users = bool(users.get("users"))
    has_roast_surface = any(
        u.get("asrep_roastable") or u.get("kerberoastable")
        for u in (users.get("users") or [])
    ) or bool(loot.get("parsed_credentials"))
    has_loot = bool(loot.get("file_count"))
    has_enum = bool(inv.get("users"))
    has_graph = (ws_path / "graph.json").is_file()
    has_exploit = bool(exploit.get("steps"))
    has_scope = bool(state.get("hosts"))

    p02 = has_scan
    p03 = has_users or has_roast_surface
    p04 = has_loot or has_roast_surface or any(
        str(c.get("source", "")).lower() in {"spray", "asreproast", "kerberoast", "loot"}
        for c in creds
    )
    p05 = bool(valid)
    p06 = has_enum
    p07 = has_graph and (acl_n > 0 or has_enum)
    p08 = has_exploit or acl_n > 0
    p09 = coerce_n > 0
    p10 = postex > 0 or has_exploit
    p11 = any(
        s.get("phase") in {"dcsync", "golden_ticket", "domain_dominance"}
        and s.get("status") == "success"
        for s in (exploit.get("steps") or [])
    )

    return {
        "p01": _st(has_scope, not has_scope),
        "p02": _st(p02, not p02),
        "p03": _st(p03, p02 and not p03),
        "p04": _st(p04, p03 and not p04 and not p05),
        "p05": _st(p05, p02 and not p05),
        "p06": _st(p06, p05 and not p06),
        "p07": _st(p07, p06 and not p07),
        "p08": _st(p08, p07 and not p08),
        "p09": _st(p09, p06 and not p09),
        "p10": _st(p10, p08 and not p10),
        "p11": _st(p11, p10 and not p11),
        "p12": _st(report, p05 and not report),
    }


def ops_phase_status(ws_path: Path) -> list[dict[str, Any]]:
    """Build dashboard UI phase bar from OPS_PHASES + workspace."""
    unified = phase_status_from_workspace(ws_path)

    def phase_st(gp: PhaseDef) -> PhaseStatus:
        statuses = [unified.get(uid, "locked") for uid in gp.unified_ids]
        if all(s == "done" for s in statuses):
            return "done"
        if any(s == "active" for s in statuses):
            return "active"
        if any(s == "done" for s in statuses):
            return "active"
        return "locked"

    by_id = {p.id: p for p in UNIFIED_PHASES}
    out: list[dict[str, Any]] = []
    for gp in OPS_PHASES:
        st = phase_st(gp)
        primary = by_id[gp.unified_ids[0]]
        out.append(
            {
                "id": gp.id,
                "code": gp.code,
                "title": gp.title,
                "tech": gp.tech,
                "status": st,
                "detail": gp.detail,
                "action": gp.action,
                "button": gp.button,
                "framework": {
                    "crtp": primary.crtp,
                    "crte": primary.crte if primary.crte != "—" else None,
                    "crto": primary.crto if primary.crto != "—" else None,
                    "mitre": list(primary.mitre_tactics),
                },
            }
        )
    return out


def build_study_map() -> list[dict[str, Any]]:
    """CRTP / CRTE / CRTO cross-reference for the manual and dashboard panel."""
    rows: list[dict[str, Any]] = []
    for ph in UNIFIED_PHASES:
        rows.append(
            {
                "id": ph.id,
                "order": ph.order,
                "name": ph.name,
                "summary": ph.summary,
                "mitre": list(ph.mitre_tactics),
                "crtp": ph.crtp,
                "crte": ph.crte,
                "crto": ph.crto,
                "artifact": ph.artifact,
                "cli": ph.cli_hint,
            }
        )
    return rows


def methodology_progress_lines(ws_path: Path) -> list[str]:
    """Unified methodology block for engagement map / terminal summary."""
    status = phase_status_from_workspace(ws_path)
    lines: list[str] = ["", "  CADENA AD (P1–P12)"]
    for ph in UNIFIED_PHASES:
        st = status.get(ph.id, "locked")
        mark = "✓" if st == "done" else ("·" if st == "active" else " ")
        lines.append(f"  {mark} P{ph.order:02d} {ph.name} — {ph.summary[:56]}")
    return lines
