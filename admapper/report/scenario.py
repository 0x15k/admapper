from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from admapper.core.output import print_info, print_success, print_table, print_warning
from admapper.creds.auth_checks import load_protected_users
from admapper.creds.common import collect_gained_hashes, format_evil_winrm_pth
from admapper.escalate.edges import collect_edges_from_pivot, pick_next_edge, sort_edges
from admapper.models.user import UAC_DONT_REQ_PREAUTH, apply_uac_flags
from admapper.models.user import UserRecord
from admapper.report.engagement import _load_json

_ARTEFACT_FILES = (
    ("unauth_scan", "unauth_scan.json"),
    ("auth_inventory", "auth_inventory.json"),
    ("credentials", "credentials.json"),
    ("loot", "loot_manifest.json"),
    ("acl_findings", "acl_findings.json"),
    ("graph", "graph.json"),
    ("paths", "paths.json"),
    ("escalate", "escalate.json"),
    ("adcs", "adcs_findings.json"),
    ("postex", "postex_ops.json"),
)


def count_credentials(ws_path: Path) -> tuple[int, int]:
    """Return (valid_count, invalid_count) from credentials.json."""
    cred_data = _load_json(ws_path / "credentials.json") or {}
    valid = invalid = 0
    for cred in cred_data.get("credentials") or []:
        if str(cred.get("status")) == "valid":
            valid += 1
        else:
            invalid += 1
    return valid, invalid


def list_artefact_status(ws_path: Path) -> list[tuple[str, bool]]:
    """Label + present flag for key workspace artefacts."""
    return [(label, (ws_path / filename).is_file()) for label, filename in _ARTEFACT_FILES]


@dataclass(frozen=True)
class RankedAction:
    command: str
    reason: str
    score: int


def _best_cred_per_user(credentials: list[dict]) -> dict[str, dict]:
    """One row per username — prefer valid status over invalid."""
    best: dict[str, dict] = {}
    for cred in credentials:
        user = str(cred.get("username", "")).lower()
        if not user:
            continue
        prev = best.get(user)
        if prev is None:
            best[user] = cred
            continue
        if str(cred.get("status")) == "valid" and str(prev.get("status")) != "valid":
            best[user] = cred
    return best


def _cred_rows(ws_path: Path) -> list[list[str]]:
    data = _load_json(ws_path / "credentials.json") or {}
    rows: list[list[str]] = []
    for cred in _best_cred_per_user(data.get("credentials") or []).values():
        rows.append(
            [
                str(cred.get("id", "")),
                str(cred.get("username", "")),
                str(cred.get("status", "")),
                str(cred.get("type", "")),
                str(cred.get("source", ""))[:40],
            ]
        )
    return rows


def _loot_cred_rows(ws_path: Path) -> list[list[str]]:
    manifest = _load_json(ws_path / "loot_manifest.json") or {}
    rows: list[list[str]] = []
    for item in manifest.get("parsed_credentials") or []:
        rows.append(
            [
                str(item.get("username", "")),
                str(item.get("password", "")),
                str(item.get("confidence", "")),
                str(item.get("pattern", "")),
                str(item.get("source_file", ""))[:50],
            ]
        )
    return rows


def _access_matrix_rows(ws_path: Path) -> list[list[str]]:
    """LDAP/SMB/Kerberos/WinRM matrix by credential (ADscan/AdStrike style)."""
    protected = load_protected_users(str(ws_path))
    cred_data = _load_json(ws_path / "credentials.json") or {}
    exploit_log = _load_json(ws_path / "exploit_log.json") or {}
    machine_winrm: set[str] = set()
    for entry in exploit_log.get("new_hashes") or []:
        account = str(entry.get("account", "")).lower()
        if account:
            machine_winrm.add(account.rstrip("$"))

    rows: list[list[str]] = []
    for cred in _best_cred_per_user(cred_data.get("credentials") or []).values():
        user = str(cred.get("username", ""))
        user_l = user.lower()
        status = str(cred.get("status", ""))
        ctype = str(cred.get("type", ""))
        is_pu = user_l in protected
        is_machine = user.endswith("$") or ctype == "ntlm"

        if status != "valid":
            rows.append([user, "-", "-", "-", "-", "unverified"])
            continue

        if is_machine or user_l.rstrip("$") in machine_winrm:
            rows.append([user, "skip", "skip", "skip", "yes*", "gMSA/machine hash"])
            continue

        if is_pu:
            rows.append([user, "skip", "skip", "yes", "no*", "Protected Users"])
            continue

        rows.append([user, "yes", "yes", "?", "no*", "standard user — no DC WinRM"])
    return rows


def _pivot_findings(ws_path: Path, *, pivot: str, domain: str) -> list[str]:
    """Narrativa: con este pivot qué se encontró (loot, enum, unauth)."""
    lines: list[str] = []
    inv = _load_json(ws_path / "auth_inventory.json") or {}
    if inv:
        lines.append(
            f"  • LDAP Inventory: {len(inv.get('users') or [])} users, "
            f"{len(inv.get('groups') or [])} groups, "
            f"{len(inv.get('computers') or [])} computers"
        )

    manifest = _load_json(ws_path / "loot_manifest.json") or {}
    shares = manifest.get("shares_looted") or []
    if shares:
        lines.append(f"  • SMB loot: {manifest.get('file_count', 0)} files in {', '.join(shares)}")

    for item in manifest.get("parsed_credentials") or []:
        password = str(item.get("password") or "")
        pwd_hint = f" → password: {password}" if password else ""
        lines.append(
            f"  • Credential in file: {item.get('username')}{pwd_hint} "
            f"({item.get('source_file')}, confidence {item.get('confidence')})"
        )

    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    for finding in unauth.get("findings") or []:
        title = str(finding.get("title", ""))
        if any(k in title.lower() for k in ("null", "kerberos", "ldap", "controller")):
            lines.append(f"  • Unauth recon: {title}")

    acl = _load_json(ws_path / "acl_findings.json") or {}
    acl_for_pivot = [
        f
        for f in acl.get("findings") or []
        if str(f.get("principal", "")).lower() == pivot.lower()
    ]
    if acl_for_pivot:
        for f in acl_for_pivot[:5]:
            lines.append(
                f"  • ACL: {f.get('right')} on {f.get('target_name')} "
                f"({f.get('severity')})"
            )
    elif pivot != "(none)":
        lines.append(
            f"  • Exploitable ACLs as {pivot}: none "
            "(normal — pivot is usually loot user, not escalation principal)"
        )

    exploit_log = _load_json(ws_path / "exploit_log.json") or {}
    for entry in exploit_log.get("new_hashes") or []:
        lines.append(f"  • Hash obtained: {entry.get('account')} (gMSA/ACL)")

    if not lines:
        lines.append("  • (run start_auth and exploit to populate findings)")
    return lines


def _attack_path_rows(ws_path: Path, *, pivot: str, owned: list[str], domain: str) -> list[list[str]]:
    edges = sort_edges(
        collect_edges_from_pivot(
            pivot_user=pivot,
            owned_users=owned,
            ws_path=ws_path,
            domain=domain,
        )
    )
    rows: list[list[str]] = []
    for idx, edge in enumerate(edges[:10], start=1):
        state = "READY" if edge.ready and not edge.target_owned else "blocked"
        rows.append(
            [
                str(idx),
                edge.module,
                edge.technique,
                edge.target[:30] if edge.target else "-",
                edge.severity,
                state,
            ]
        )
    return rows


def roast_candidates_line(ws_path: Path) -> str | None:
    """AS-REP / Kerberoast candidates from auth_inventory.json user records."""
    inv = _load_json(ws_path / "auth_inventory.json") or {}
    asrep: list[str] = []
    krb: list[str] = []
    for raw in inv.get("users") or []:
        if isinstance(raw, str):
            continue
        user = UserRecord.from_dict(raw) if raw.get("username") else None
        if user is None:
            username = str(raw.get("sAMAccountName") or raw.get("username") or "")
            if not username or username.endswith("$"):
                continue
            uac = raw.get("userAccountControl") or raw.get("uac")
            spns = raw.get("servicePrincipalName") or raw.get("spns") or []
            if isinstance(spns, str):
                spns = [spns]
            user = apply_uac_flags(
                UserRecord(username=username, uac=int(uac) if uac is not None else None, spns=list(spns))
            )
        if user.is_machine_account or not user.enabled:
            continue
        if user.asrep_roastable or (user.uac is not None and user.uac & UAC_DONT_REQ_PREAUTH):
            asrep.append(user.username)
        elif user.kerberoastable:
            krb.append(user.username)
    if not asrep and not krb:
        return None
    parts: list[str] = []
    if asrep:
        parts.append(f"asrep: {', '.join(asrep[:8])}")
    if krb:
        parts.append(f"kerberoast: {', '.join(krb[:8])}")
    return " | ".join(parts)


def infer_kill_chain_phase(ws_path: Path, owned: list[str]) -> str:
    exploit_log = _load_json(ws_path / "exploit_log.json") or {}
    if exploit_log.get("new_hashes"):
        return "Phase 4 — Lateral / WinRM (machine account)"
    cred_data = _load_json(ws_path / "credentials.json") or {}
    pending_loot = any(
        str(c.get("status")) != "valid"
        for c in cred_data.get("credentials") or []
        if str(c.get("source")) == "share_loot"
    )
    if pending_loot:
        return "Phase 3 — Privilege escalation (pending loot credentials)"
    if owned:
        return "Phase 2 — Authenticated enum (active pivot)"
    loot = _load_json(ws_path / "loot_manifest.json")
    if loot:
        return "Phase 1 — Loot / cred harvesting"
    return "Phase 0 — Unauth recon"


def _is_gmsa_edge(edge) -> bool:
    target = (getattr(edge, "target", None) or "").lower()
    tech = (getattr(edge, "technique", None) or "").lower()
    if tech not in {"genericwrite", "readgmsapassword", "genericall"}:
        return False
    return target.endswith("$") or "msa_" in target


def _edge_to_command(edge, *, workspace: str, ws_path: Path | None = None) -> str:
    if _is_gmsa_edge(edge):
        from admapper.creds.kerberos_skew import load_workspace_clock_skew

        skew = load_workspace_clock_skew(ws_path) if ws_path else None
        skew_arg = f" --clock-skew '{skew}'" if skew else ""
        op_id = getattr(edge, "op_id", None) or ""
        if op_id:
            return f"admapper exploit -w {workspace}{skew_arg}  # or: acls show {op_id}"
        return f"admapper exploit -w {workspace}{skew_arg}"
    if edge.manual_commands:
        return edge.manual_commands[0]
    if edge.op_id:
        return f"admapper {edge.module} run --op {edge.op_id} -w {workspace}"
    return f"admapper {edge.module} -w {workspace}  # {edge.title}"


def _loot_verify_actions(
    ws_path: Path,
    *,
    workspace: str,
    protected: set[str],
) -> list[RankedAction]:
    cred_data = _load_json(ws_path / "credentials.json") or {}
    loot = _load_json(ws_path / "loot_manifest.json") or {}
    unauth = _load_json(ws_path / "unauth_scan.json") or {}
    dc_ip = str(loot.get("dc_ip") or "")
    if not dc_ip:
        for host in unauth.get("hosts") or []:
            if host.get("is_domain_controller"):
                dc_ip = str(host.get("address", ""))
                break
        if not dc_ip and unauth.get("hosts"):
            dc_ip = str(unauth["hosts"][0].get("address", ""))

    best = _best_cred_per_user(cred_data.get("credentials") or [])
    actions: list[RankedAction] = []
    seen_users: set[str] = set()
    for item in loot.get("parsed_credentials") or []:
        user = str(item.get("username", "")).lower()
        if not user or user in seen_users:
            continue
        seen_users.add(user)
        match = best.get(user)
        if match and str(match.get("status")) == "valid":
            continue
        password = str(item.get("password") or "")
        if user in protected and password and dc_ip:
            cmd = (
                f"admapper run -H {dc_ip} -u {user} -p '{password}' "
                f"-w {workspace} --clock-skew '+7h'"
            )
        elif match:
            cmd = f"start_auth --cred-id {match.get('id')}  # verify → acls → exploit"
        else:
            cmd = f"jq '.parsed_credentials' {ws_path}/loot_manifest.json"
        actions.append(RankedAction(command=cmd, reason=f"loot cred pending: {user}", score=85))
    return actions


def resolve_top_actions(
    ws_path: Path,
    *,
    pivot: str,
    owned: list[str],
    domain: str,
    workspace: str,
    limit: int = 3,
) -> list[RankedAction]:
    """Rank up to `limit` next steps from escalate edges, loot creds, and ACL gaps."""
    protected = {u.lower() for u in load_protected_users(str(ws_path))}
    candidates: list[RankedAction] = []

    hashes = collect_gained_hashes(ws_path)
    pivot_l = pivot.lower()
    pivot_is_machine = pivot.endswith("$")
    last_machine_idx = max(
        (i for i, user in enumerate(owned) if user.endswith("$")),
        default=-1,
    )
    post_machine_humans = [
        user
        for i, user in enumerate(owned)
        if i > last_machine_idx and not user.endswith("$")
    ]
    suggest_machine_pth = pivot_is_machine and not post_machine_humans
    if hashes and suggest_machine_pth:
        account, nthash = hashes[-1]
        if pivot_l.rstrip("$") in account.lower() or account.lower() in pivot_l:
            host, winrm_cmd = format_evil_winrm_pth(
                account=account,
                nthash=nthash,
                domain=domain,
                ws_path=ws_path,
            )
            candidates.append(
                RankedAction(
                    command=winrm_cmd,
                    reason=f"WinRM PTH with {account} (postex)",
                    score=95,
                )
            )
            candidates.append(
                RankedAction(
                    command=(
                        f"admapper winrm -H {host} -d {domain} -u '{account}' "
                        f"--hash {nthash} -x whoami"
                    ),
                    reason="native postex shell",
                    score=92,
                )
            )

    edges = collect_edges_from_pivot(
        pivot_user=pivot,
        owned_users=owned,
        ws_path=ws_path,
        domain=domain,
    )

    for edge in sort_edges(edges):
        if not edge.ready or edge.target_owned or edge.technique == "member_of":
            continue
        sev = {"critical": 40, "high": 30, "medium": 20, "low": 10}.get(edge.severity.lower(), 5)
        tech = {"forcechangepassword": 15, "genericall": 14, "wsus_cert_chain": 13}.get(
            edge.technique.lower(), 8
        )
        candidates.append(
            RankedAction(
                command=_edge_to_command(edge, workspace=workspace, ws_path=ws_path),
                reason=f"{edge.module}/{edge.technique}: {edge.title}",
                score=sev + tech,
            )
        )

    candidates.extend(_loot_verify_actions(ws_path, workspace=workspace, protected=protected))

    cred_data = _load_json(ws_path / "credentials.json") or {}
    for user, cred in _best_cred_per_user(cred_data.get("credentials") or []).items():
        if user.startswith("svc_") and str(cred.get("status")) != "valid":
            candidates.append(
                RankedAction(
                    command=f"start_auth --cred-id {cred.get('id')}  # verify → acls → exploit",
                    reason=f"svc cred unverified: {user}",
                    score=70,
                )
            )

    if not (_load_json(ws_path / "acl_findings.json") or {}).get("findings"):
        candidates.append(
            RankedAction(
                command=f"acls  # shell, o: admapper analyst -w {workspace}",
                reason="ACL enum not run",
                score=25,
            )
        )

    roast = roast_candidates_line(ws_path)
    if roast:
        candidates.append(
            RankedAction(
                command="asreproast  # o kerberoast — shell",
                reason=f"ROAST CANDIDATES: {roast}",
                score=60,
            )
        )

    for edge in sort_edges(edges):
        if edge.ready or edge.target_owned:
            continue
        detail = edge.summary[:60] if edge.summary else "check prerequisites"
        candidates.append(
            RankedAction(
                command=f"Block: {edge.title} — {detail}",
                reason="blocked edge",
                score=5,
            )
        )

    candidates.append(
        RankedAction(
            command=f"admapper analyst -w {workspace}",
            reason="refresh analyst view",
            score=1,
        )
    )

    seen: set[str] = set()
    ranked: list[RankedAction] = []
    for action in sorted(candidates, key=lambda a: (-a.score, a.command)):
        if action.command in seen:
            continue
        seen.add(action.command)
        ranked.append(action)
        if len(ranked) >= limit:
            break
    return ranked


def resolve_next_command(
    ws_path: Path,
    *,
    pivot: str,
    owned: list[str],
    domain: str,
    workspace: str,
) -> str:
    """Single best next command (top-ranked action)."""
    top = resolve_top_actions(
        ws_path,
        pivot=pivot,
        owned=owned,
        domain=domain,
        workspace=workspace,
        limit=1,
    )
    if top:
        return top[0].command

    edges = collect_edges_from_pivot(
        pivot_user=pivot,
        owned_users=owned,
        ws_path=ws_path,
        domain=domain,
    )
    nxt = pick_next_edge(edges)
    if nxt:
        return _edge_to_command(nxt, workspace=workspace, ws_path=ws_path)
    return f"admapper analyst -w {workspace}"


def build_scenario_report(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
) -> str:
    owned = list(owned_users or [])
    pivot = pivot_user or (owned[-1] if owned else "(none)")
    domain = domain or "(no domain)"
    phase = infer_kill_chain_phase(ws_path, owned)

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

    lines = [
        "═" * 64,
        "  ADMAPPER ANALYST  (scenario — ADscan / AdStrike Smart Analyst style)",
        "═" * 64,
        f"  Workspace : {workspace}",
        f"  Domain    : {domain}",
        f"  DC        : {dc_ip or '-'} ({dc_host or 'no PTR'})",
        f"  Pivot     : {pivot}",
        f"  Owned     : {', '.join(owned) if owned else '(none)'}",
        f"  Phase     : {phase}",
        "",
        f"FOUND WITH {pivot.upper()}",
        "─" * 64,
        *_pivot_findings(ws_path, pivot=pivot, domain=domain),
        "",
        "ACCESS MATRIX (validated / inferred)",
        "─" * 64,
        "  user                 ldap  smb  krb  winrm   note",
    ]
    for row in _access_matrix_rows(ws_path):
        lines.append(
            f"  {row[0]:<20} {row[1]:<5} {row[2]:<5} {row[3]:<5} {row[4]:<5} {row[5]}"
        )

    roast_line = roast_candidates_line(ws_path)
    if roast_line:
        lines.extend(
            [
                "",
                "ROAST CANDIDATES",
                "─" * 64,
                f"  {roast_line}",
            ]
        )

    lines.extend(["", "ATTACK PATHS (1-hop from pivot)", "─" * 64])
    path_rows = _attack_path_rows(ws_path, pivot=pivot, owned=owned, domain=domain)
    if path_rows:
        for row in path_rows:
            lines.append(
                f"  #{row[0]} [{row[5]}] {row[1]}/{row[2]} → {row[3]} ({row[4]})"
            )
    else:
        lines.append("  (no paths — obtain loot credential or change pivot)")

    top_actions = resolve_top_actions(
        ws_path,
        pivot=pivot,
        owned=owned,
        domain=domain,
        workspace=workspace,
        limit=3,
    )
    lines.extend(["", "RECOMMENDED ACTIONS (top 3)", "─" * 64])
    for idx, action in enumerate(top_actions, start=1):
        tag = "RECOMMENDED" if idx == 1 else f"#{idx}"
        lines.append(f"  [{tag}] {action.command}")
        if action.reason and idx == 1:
            lines.append(f"         ({action.reason})")

    lines.extend(
        [
            "",
            f"  Workspace: {ws_path}",
            "═" * 64,
            "",
        ]
    )
    return "\n".join(lines)


def print_scenario_report(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
) -> None:
    """Smart Analyst: escenario + tablas en terminal."""
    text = build_scenario_report(
        ws_path,
        workspace=workspace,
        domain=domain,
        owned_users=owned_users,
        pivot_user=pivot_user,
    )
    print_success("ADMapper Analyst — engagement scenario")
    for line in text.splitlines():
        if line.startswith("RECOMMENDED ACTIONS") or line.startswith("ROAST CANDIDATES"):
            print_info(line)
        elif line.startswith("  [RECOMMENDED]") or line.startswith("  [#"):
            print_warning(line)
        elif line.startswith("  admapper") or line.startswith("  start_auth") or line.startswith("  acls"):
            print_warning(line)
        elif line.startswith("  Blocker:"):
            print_warning(line)
        else:
            print(line)

    cred_rows = _cred_rows(ws_path)
    if cred_rows:
        print_table(
            "Credentials",
            ["id", "user", "status", "type", "source"],
            cred_rows,
        )
    loot_rows = _loot_cred_rows(ws_path)
    if loot_rows:
        print_table(
            "Loot passwords",
            ["user", "password", "confidence", "pattern", "file"],
            loot_rows,
        )
    access = _access_matrix_rows(ws_path)
    if access:
        print_table(
            "Access by credential",
            ["user", "ldap", "smb", "kerberos", "winrm", "note"],
            access,
        )
