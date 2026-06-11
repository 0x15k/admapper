from __future__ import annotations

from pathlib import Path

from admapper.report.engagement import _load_json


def methodology_lines(ws_path: Path) -> list[str]:
    """Kill-chain rollup — also exported from ``admapper.engagement``."""
    from admapper.methodology.unified import methodology_progress_lines

    lines: list[str] = methodology_progress_lines(ws_path)
    lines.extend(["", "  PROGRESO OPERATIVO"])

    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    if unauth.get("hosts"):
        findings = unauth.get("findings") or []
        medium = [f for f in findings if str(f.get("severity")) == "medium"]
        hint = f", {len(medium)} hallazgo(s) medium" if medium else ""
        lines.append(f"  ✓ P0 Recon sin creds — dominio inferido{hint}")
    else:
        lines.append("  · P0 Recon sin creds — pendiente (admapper scan -H <DC>)")

    cred_data = _load_json(ws_path / "credentials.json") or {}
    creds = cred_data.get("credentials") or []
    valid = [c for c in creds if str(c.get("status")) == "valid"]
    invalid = [c for c in creds if str(c.get("status")) != "valid"]
    if valid:
        users = ", ".join(sorted({str(c.get("username")) for c in valid})[:4])
        extra = f" (+{len(valid) - 4})" if len(valid) > 4 else ""
        lines.append(f"  ✓ P1 Credenciales — {len(valid)} válida(s): {users}{extra}")
    else:
        lines.append("  · P1 Credenciales — ninguna válida aún")

    inv = _load_json(ws_path / "auth_inventory.json") or {}
    if inv:
        users_n = len(inv.get("users") or [])
        groups_n = len(inv.get("groups") or [])
        computers_n = len(inv.get("computers") or [])
        deleg_n = len(inv.get("delegations") or [])
        shares = inv.get("smb_shares") or []
        share_s = f", SMB: {len(shares)} shares" if shares else ""
        del_s = f", {deleg_n} delegación(es)" if deleg_n else ""
        lines.append(
            f"  ✓ P2 Enum autenticada — {users_n} users, {groups_n} groups, "
            f"{computers_n} computers{del_s}{share_s}"
        )
    elif valid:
        lines.append("  · P2 Enum autenticada — pendiente (start_auth / run con creds)")
    else:
        lines.append("  · P2 Enum autenticada — (requiere credencial válida)")

    loot = _load_json(ws_path / "loot_manifest.json") or {}
    if loot.get("file_count"):
        parsed = loot.get("parsed_credentials") or []
        lines.append(
            f"  ✓ P3 Loot SMB — {loot.get('file_count')} archivo(s), "
            f"{len(parsed)} cred(s) parseada(s)"
        )
    elif valid:
        lines.append("  · P3 Loot SMB — pendiente (exploit / share_loot)")
    else:
        lines.append("  · P3 Loot SMB — (requiere credencial)")

    acl = _load_json(ws_path / "acl_findings.json") or {}
    acl_n = int(acl.get("finding_count") or len(acl.get("findings") or []))
    if acl_n:
        lines.append(f"  ✓ P4 ACLs — {acl_n} ruta(s) de abuso para owned")
    elif inv:
        lines.append("  · P4 ACLs — sin rutas (admapper acls)")
    else:
        lines.append("  · P4 ACLs — pendiente")

    exploit = _load_json(ws_path / "exploit_log.json") or {}
    if exploit.get("steps"):
        new_u = exploit.get("new_users") or []
        suffix = f", owned+: {', '.join(new_u)}" if new_u else ""
        lines.append(f"  ✓ P5 Exploit — {len(exploit.get('steps') or [])} paso(s){suffix}")
    elif acl_n:
        lines.append("  · P5 Exploit — pendiente (admapper exploit)")

    postex = _load_json(ws_path / "postex_scan.json") or {}
    pf = postex.get("findings") or []
    if pf:
        lines.append(f"  ✓ P6 Post-ex local — {len(pf)} oportunidad(es)")
    elif exploit.get("new_hashes"):
        lines.append("  · P6 Post-ex — pendiente (postex scan)")

    if invalid and not valid:
        lines.append(f"  ! {len(invalid)} credencial(es) en store sin validar — revisar loot")

    return lines


def enum_highlights(ws_path: Path) -> list[str]:
    """Actionable enum facts — not duplicated in per-step banners."""
    lines: list[str] = []
    inv = _load_json(ws_path / "auth_inventory.json") or {}
    if not inv:
        return lines

    lines.append("")
    lines.append("  ENUM DESTACADA")

    delegations = inv.get("delegations") or []
    for d in delegations[:3]:
        dtype = str(d.get("delegation_type") or "?")
        name = str(d.get("object_name") or d.get("dn", ""))[:40]
        lines.append(f"  · delegación {dtype}: {name}")

    gmsa = [
        c
        for c in inv.get("computers") or []
        if "managed service accounts" in str(c.get("dn", "")).lower()
        or str(c.get("name", "")).lower().startswith("msa_")
    ]
    for c in gmsa[:4]:
        lines.append(f"  · gMSA: {c.get('name')} ({c.get('dns_host', '-')})")

    if inv.get("adcs_present"):
        lines.append("  · AD CS presente en el bosque")

    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    for f in unauth.get("findings") or []:
        if "null session" in str(f.get("title", "")).lower():
            lines.append(f"  · {f.get('title')} — {f.get('detail', '')[:60]}")
            break

    errors = [str(e) for e in (inv.get("errors") or []) if e]
    if errors:
        lines.append(f"  · enum parcial: {errors[0][:70]}")

    return lines
