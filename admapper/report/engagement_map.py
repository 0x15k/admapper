from __future__ import annotations

from pathlib import Path

from admapper.core.output import print_success, print_warning
from admapper.creds.auth_checks import load_protected_users
from admapper.creds.common import (
    collect_gained_hashes,
    format_admapper_winrm_pth,
    format_evil_winrm_pth,
)
from admapper.creds.kerberos_skew import load_workspace_clock_skew
from admapper.escalate.edges import collect_edges_from_pivot, pick_next_edge, sort_edges
from admapper.models.escalation import EscalationEdge
from admapper.report.engagement import _load_json
from admapper.report.methodology import enum_highlights, methodology_lines
from admapper.report.scenario import _access_matrix_rows, _best_cred_per_user


def _is_gmsa_target(name: str) -> bool:
    target = name.lower()
    return target.endswith("$") or "msa_" in target


def _edge_command(edge: EscalationEdge, *, workspace: str, ws_path: Path) -> str:
    """Map technique to the correct ADMapper command (not generic manual_commands)."""
    tech = edge.technique.lower()
    target = (edge.target or "").lower()
    if tech in {"genericwrite", "readgmsapassword", "genericall"} and _is_gmsa_target(target):
        if edge.op_id:
            return f"admapper exploit -w {workspace}  # or: acls show {edge.op_id}"
        return f"admapper exploit -w {workspace}"

    if edge.op_id:
        return f"admapper {edge.module} run --op {edge.op_id} -w {workspace}"
    if edge.manual_commands:
        return edge.manual_commands[0]
    return f"admapper {edge.module} -w {workspace}  # {edge.title}"


def _edge_technique_detail(edge: EscalationEdge) -> str:
    tech = edge.technique.lower()
    if tech == "genericwrite" and _is_gmsa_target(edge.target or ""):
        return "patch msDS-GroupMSAMembership → read gMSA password"
    if tech == "readgmsapassword":
        return "read gMSA managed password (nxc --gmsa)"
    if tech == "dll_hijack_scheduled_task":
        return edge.summary[:80] if edge.summary else "scheduled task DLL hijack"
    if tech == "wsus_cert_chain":
        return "WSUS spoof → AD CS enrollment → DA cert"
    return edge.summary[:80] if edge.summary else edge.title


def loot_clue_rows(ws_path: Path) -> list[dict[str, str]]:
    """Strings extracted from loot files — never substituted with verified secrets."""
    manifest = _load_json(ws_path / "loot_manifest.json") or {}
    cred_data = _load_json(ws_path / "credentials.json") or {}
    best = _best_cred_per_user(cred_data.get("credentials") or [])
    clues: list[dict[str, str]] = []

    for item in manifest.get("parsed_credentials") or []:
        user = str(item.get("username", ""))
        if not user:
            continue
        match = best.get(user.lower())
        if match and str(match.get("status")) == "valid":
            state = "verificado"
        elif match:
            state = str(match.get("status", "sin verificar"))
        else:
            state = "sin verificar"
        clues.append(
            {
                "user": user,
                "string": str(item.get("password", "")),
                "source": str(item.get("source_file", "")),
                "confidence": str(item.get("confidence", "")),
                "pattern": str(item.get("pattern", "")),
                "verify_state": state,
            }
        )
    return clues


def _discovered_cred_rows(ws_path: Path) -> list[list[str]]:
    """CLI table: loot file string + verification state (not the working password)."""
    rows: list[list[str]] = []
    for clue in loot_clue_rows(ws_path):
        rows.append(
            [
                clue["user"],
                clue["string"],
                clue["verify_state"],
                clue["source"][:28],
            ]
        )
    return rows


def _acl_exploit_blocker(ws_path: Path) -> str | None:
    log = _load_json(ws_path / "exploit_log.json") or {}
    steps = log.get("steps") or []
    if any(
        s.get("phase") == "acl_exploit" and s.get("status") == "success" for s in steps
    ):
        return None
    for step in reversed(steps):
        if step.get("phase") != "acl_exploit" or step.get("status") != "skipped":
            continue
        detail = str(step.get("detail", "")).strip()
        if not detail:
            return "exploit ACL omitido — revisa exploit_log.json"
        detail_l = detail.lower()
        if "krb5" in detail_l or "kinit" in detail_l or "mit krb5" in detail_l:
            from admapper.core.platform import mit_krb5_install_hint

            return f"Falta MIT krb5 — {mit_krb5_install_hint()}"
        if "http service ticket" in detail_l:
            return (
                "gMSA necesita solo TGT (no ticket HTTP WinRM) — "
                "actualiza admapper y vuelve a ejecutar brief"
            )
        if "clock skew" in detail_l or "krb_ap_err_skew" in detail_l:
            skew = load_workspace_clock_skew(ws_path)
            if skew:
                return (
                    f"Kerberos clock skew (offset {skew}) — "
                    "sincroniza con sntp o `admapper run --clock-skew` y re-ejecuta exploit"
                )
            creds = (_load_json(ws_path / "credentials.json") or {}).get("credentials") or []
            valid_users = {
                str(c.get("username", "")).lower()
                for c in creds
                if str(c.get("status")) == "valid"
            }
            # Stale skew from an earlier attempt — cred already verifies at system time.
            if valid_users:
                return None
            return (
                "Kerberos clock skew — sincroniza reloj (`sntp -sS <DC_IP>`) "
                "o instala libfaketime y re-ejecuta exploit"
            )
        return detail[:220]
    return None


def _hash_section_lines(ws_path: Path, *, domain: str | None) -> list[str]:
    hashes = collect_gained_hashes(ws_path)
    if not hashes:
        return []
    lines = ["", "  HASH OBTENIDO"]
    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    dc_ip = ""
    for host in unauth.get("hosts") or []:
        if host.get("is_domain_controller"):
            dc_ip = str(host.get("address", ""))
            break
    for account, nthash in hashes:
        _, winrm_cmd = format_evil_winrm_pth(
            account=account,
            nthash=nthash,
            domain=domain,
            ws_path=ws_path,
            fallback_ip=dc_ip or None,
        )
        lines.append(f"  {account:<14}: {nthash}")
        lines.append(f"  WinRM          : {winrm_cmd}")
    return lines


def _winrm_confirmed(ws_path: Path, account: str) -> bool:
    """True when lateral probe or postex scan already validated WinRM for account."""
    account_l = account.lower().rstrip("$")
    log = _load_json(ws_path / "exploit_log.json") or {}
    for step in log.get("steps") or []:
        phase = str(step.get("phase") or "")
        if not phase.startswith("lateral_winrm"):
            continue
        if str(step.get("status") or "").lower() != "success":
            continue
        detail = str(step.get("detail") or "").lower()
        if account_l in detail:
            return True

    scan = _load_json(ws_path / "postex_scan.json") or {}
    shell_user = str(scan.get("shell_user") or "").lower().rstrip("$")
    if shell_user and shell_user == account_l:
        return True

    for row in _access_matrix_rows(ws_path):
        user = str(row[0] or "").lower().rstrip("$")
        winrm = str(row[4] or "").lower()
        if user == account_l and winrm.startswith("sí"):
            return True
    return False


def _winrm_next_hop_lines(
    ws_path: Path,
    *,
    domain: str | None,
    workspace: str,
) -> list[str]:
    hashes = collect_gained_hashes(ws_path)
    if not hashes:
        return []
    account, nthash = hashes[-1]
    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    dc_ip = ""
    for host in unauth.get("hosts") or []:
        if host.get("is_domain_controller"):
            dc_ip = str(host.get("address", ""))
            break
    host, winrm_cmd = format_evil_winrm_pth(
        account=account,
        nthash=nthash,
        domain=domain,
        ws_path=ws_path,
        fallback_ip=dc_ip or None,
    )
    _, admapper_cmd = format_admapper_winrm_pth(
        account=account,
        nthash=nthash,
        domain=domain,
        ws_path=ws_path,
        fallback_ip=dc_ip or None,
    )
    return [
        "",
        "  SIGUIENTE PASO  [listo]",
        f"  {account} ──WinRM──► {host}",
        "  Técnica   : Pass-the-Hash → shell remota (postex)",
        f"  Comando   : {winrm_cmd}",
        f"  Alt       : {admapper_cmd}",
    ]


def _format_edge_line(
    edge: EscalationEdge,
    *,
    pivot: str,
    workspace: str,
    ws_path: Path,
) -> list[str]:
    target = edge.target or "?"
    if _is_gmsa_target(target) and not target.endswith("$"):
        target = f"{target} (gMSA)"
    return [
        f"  {pivot} ──{edge.technique}──► {target}",
        f"  Técnica   : {_edge_technique_detail(edge)}",
        f"  Comando   : {_edge_command(edge, workspace=workspace, ws_path=ws_path)}",
    ]


def build_engagement_map(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
) -> str:
    owned = list(owned_users or [])
    pivot = pivot_user or (owned[-1] if owned else "(ninguno)")
    domain = domain or "(sin dominio)"
    protected = load_protected_users(str(ws_path))

    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    dc_ip = ""
    dc_host = ""
    for host in unauth.get("hosts") or []:
        if host.get("is_domain_controller"):
            dc_ip = str(host.get("address", ""))
            dc_host = str(host.get("hostname") or "")
            break
    if not dc_ip and unauth.get("hosts"):
        dc_ip = str(unauth["hosts"][0].get("address", ""))
        dc_host = str(unauth["hosts"][0].get("hostname") or "")

    pivot_note = ""
    if pivot.lower() in protected:
        pivot_note = " (Protected Users — Kerberos only)"

    lines = [
        "═" * 39,
        "  MAPA DE ENGAGEMENT  (estilo BloodHound)",
        "═" * 39,
        f"  Dominio   : {domain}",
        f"  DC        : {dc_ip or '-'} ({dc_host or 'sin PTR'})",
        "",
        "  ESTÁS AQUÍ",
        f"  ● owned   : {', '.join(owned) if owned else '(ninguno)'}",
        f"  ● pivot   : {pivot}{pivot_note}",
    ]
    lines.extend(methodology_lines(ws_path))
    lines.extend(enum_highlights(ws_path))

    cred_rows = _discovered_cred_rows(ws_path)
    if cred_rows:
        lines.extend(["", "  CREDENCIALES DESCUBIERTAS"])
        col_w = [17, 20, 10, 28]
        header = ["user", "password (loot)", "verified", "source"]
        lines.append(
            "  ┌"
            + "┬".join("─" * w for w in col_w)
            + "┐"
        )
        lines.append(
            "  │ "
            + " │ ".join(h.center(w) for h, w in zip(header, col_w, strict=True))
            + " │"
        )
        lines.append(
            "  ├"
            + "┼".join("─" * w for w in col_w)
            + "┤"
        )
        for row in cred_rows:
            cells = [
                (row[0][: col_w[0] - 1]).ljust(col_w[0]),
                (row[1][: col_w[1] - 1]).ljust(col_w[1]),
                (row[2][: col_w[2] - 1]).center(col_w[2]),
                (row[3][: col_w[3] - 1]).ljust(col_w[3]),
            ]
            lines.append("  │ " + " │ ".join(cells) + " │")
        lines.append(
            "  └"
            + "┴".join("─" * w for w in col_w)
            + "┘"
        )
        lines.append(
            "  * cadena del archivo = pista — el operador decide qué probar (creds add / verify)"
        )

    lines.extend(_hash_section_lines(ws_path, domain=domain))

    from admapper.core.verbosity import is_verbose

    if is_verbose():
        pw_data = _load_json(ws_path / "password_candidates.json") or {}
        wordlist = pw_data.get("wordlist") or []
        if wordlist:
            lines.append(
                f"  (verbose) variantes internas → {ws_path / 'password_candidates.json'}"
            )

    intel = _load_json(ws_path / "user_intel.json") or {}
    intel_users = intel.get("users") or []
    loot_anomalies = [
        u
        for u in intel_users
        if "share_loot" in (u.get("sources") or [])
        and str(u.get("cred_status", "")).lower() not in {"valid", "verified"}
    ]
    if loot_anomalies:
        lines.extend(["", "  LOOT SIN VERIFICAR (usuario en LDAP, cred pendiente)"])
        for u in loot_anomalies[:6]:
            lines.append(
                f"  {u.get('username'):<20} cred={u.get('cred_status') or 'pendiente'}  "
                f"→ creds add + creds verify"
            )

    acl_blocker = _acl_exploit_blocker(ws_path)
    if acl_blocker:
        lines.extend(
            [
                "",
                "  ⚠ BLOQUEO",
                f"  {acl_blocker}",
            ]
        )

    edges = collect_edges_from_pivot(
        pivot_user=pivot,
        owned_users=owned,
        ws_path=ws_path,
        domain=domain,
    )
    next_edge = pick_next_edge(edges)
    blocked: list[EscalationEdge] = []

    hashes = collect_gained_hashes(ws_path)
    winrm_hop: list[str] = []
    if hashes:
        latest_account, _ = hashes[-1]
        if not _winrm_confirmed(ws_path, latest_account):
            winrm_hop = _winrm_next_hop_lines(ws_path, domain=domain, workspace=workspace)
    if winrm_hop:
        lines.extend(winrm_hop)
    elif next_edge:
        lines.extend(["", "  SIGUIENTE PASO  [listo]"])
        lines.extend(
            _format_edge_line(
                next_edge,
                pivot=pivot,
                workspace=workspace,
                ws_path=ws_path,
            )
        )
    else:
        scan = _load_json(ws_path / "postex_scan.json") or {}
        findings = scan.get("findings") or []
        if findings and pivot.endswith("$"):
            f = findings[0]
            run_as = str(f.get("run_as_user") or "?")
            zip_name = str(f.get("payload_zip") or "payload.zip")
            drop = str(f.get("drop_path") or "?")
            task = str(f.get("task_name") or f.get("technique") or "scheduled task")
            lines.extend(
                [
                    "",
                    "  SIGUIENTE PASO  [listo]",
                    f"  {pivot} ──dll_hijack_scheduled_task──► {run_as}",
                    f"  Técnica   : {task} → {drop}\\{zip_name}",
                    f"  Comando   : admapper postex run -w {workspace}",
                ]
            )

    for edge in sort_edges(edges):
        if edge.technique == "member_of":
            continue
        if edge is next_edge:
            continue
        if edge.ready and not edge.target_owned:
            continue
        blocked.append(edge)

    if blocked:
        lines.extend(["", "  BLOQUEADO / DESPUÉS"])
        for edge in blocked[:5]:
            state = "bloqueado" if not edge.ready else "owned"
            lines.append(f"  {edge.target} ──{edge.technique}──► {edge.module} ({state})")

    access = _access_matrix_rows(ws_path)
    owned_l = {u.lower() for u in owned}
    access_owned = [row for row in access if str(row[0]).lower() in owned_l]
    if access_owned:
        lines.extend(["", "  ACCESO PIVOT / OWNED (ldap · smb · krb · winrm)"])
        lines.append("  usuario              ldap  smb  krb  winrm   nota")
        for row in access_owned:
            lines.append(
                f"  {row[0]:<20} {row[1]:<5} {row[2]:<5} {row[3]:<5} {row[4]:<5} {row[5]}"
            )

    lines.extend(["", "═" * 39, ""])
    return "\n".join(lines)


def build_engagement_summary(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
) -> dict[str, object]:
    """Structured rollup for game UI / compact terminal (learner-friendly)."""
    owned = list(owned_users or [])
    pivot = pivot_user or (owned[-1] if owned else "")
    domain_s = domain or "(sin dominio)"
    from admapper.report.methodology import methodology_lines

    phases = [
        ln.strip().lstrip("✓·").strip()
        for ln in methodology_lines(ws_path)
        if ln.strip().startswith(("✓", "·"))
    ]
    acl_blocker = _acl_exploit_blocker(ws_path)
    edges = collect_edges_from_pivot(
        pivot_user=pivot,
        owned_users=owned,
        ws_path=ws_path,
        domain=domain_s,
    )
    next_edge = pick_next_edge(edges)
    next_title = ""
    next_technique = ""
    if next_edge:
        next_title = (
            f"{pivot} ──{next_edge.technique}──► {next_edge.target}"
            if pivot
            else next_edge.title
        )
        next_technique = _edge_technique_detail(next_edge)

    return {
        "domain": domain_s,
        "owned": owned,
        "pivot": pivot,
        "phases": phases,
        "blocker": acl_blocker,
        "next_title": next_title,
        "next_technique": next_technique,
        "workspace": workspace,
    }


def format_engagement_summary_lines(summary: dict[str, object]) -> list[str]:
    lines = ["── RESUMEN ──"]
    owned = summary.get("owned") or []
    pivot = summary.get("pivot") or "—"
    lines.append(f"Owned: {', '.join(owned) if owned else '—'} · Pivot: {pivot}")
    for phase in (summary.get("phases") or [])[:6]:
        lines.append(f"  ✓ {phase}")
    blocker = summary.get("blocker")
    if blocker:
        lines.append(f"⚠ Bloqueo: {blocker}")
    next_title = summary.get("next_title")
    if next_title:
        lines.append(f"→ Siguiente: {next_title}")
        tech = summary.get("next_technique")
        if tech:
            lines.append(f"  {tech}")
    return lines


def print_engagement_map(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
) -> None:
    from admapper.core.verbosity import is_compact

    if is_compact():
        summary = build_engagement_summary(
            ws_path,
            workspace=workspace,
            domain=domain,
            owned_users=owned_users,
            pivot_user=pivot_user,
        )
        from admapper.core.output import print_info, print_success, print_warning

        for line in format_engagement_summary_lines(summary):
            if line.startswith("⚠"):
                print_warning(line.removeprefix("⚠ ").strip())
            elif line.startswith("Owned") or line.startswith("  ✓"):
                print_success(line)
            else:
                print_info(line)
        return

    text = build_engagement_map(
        ws_path,
        workspace=workspace,
        domain=domain,
        owned_users=owned_users,
        pivot_user=pivot_user,
    )
    print_success("ADMapper — mapa de engagement")
    for line in text.splitlines():
        if line.startswith("  ⚠") or "BLOQUEO" in line:
            print_warning(line)
        elif line.startswith("  SIGUIENTE PASO") or "[listo]" in line:
            print_warning(line)
        elif line.startswith("  HASH OBTENIDO"):
            print_success(line)
        elif line.startswith("  ") and ": " in line and len(line.split(": ", 1)[-1]) == 32:
            print_success(line)
        else:
            print(line)
