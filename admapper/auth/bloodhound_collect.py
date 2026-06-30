"""BloodHound-python collection for workspace ``bloodhound/`` directory.

Runs the external ``bloodhound-python`` ingestor (not SharpHound) with workspace
credentials, writes CE-compatible JSON under ``workspaces/<name>/bloodhound/``,
then refreshes ``bloodhound_overlay.json`` for the dashboard graph layer.

Does **not** modify ``graph.json`` — overlay merge is handled separately.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from admapper.auth.start_auth import _pick_credential
from admapper.creds.common import pick_dc_ip
from admapper.models.credential import Credential, CredentialType
from admapper.support.platform import resolve_executable

if TYPE_CHECKING:
    from admapper.support.session import Session

# bloodhound-python collection methods (see ``bloodhound-python -h``).
DEFAULT_COLLECT = "All"
STEALTH_COLLECT = "DCOnly"
OUTPUT_PREFIX = "admapper"


@dataclass
class BloodhoundCollectResult:
    output_dir: Path
    command: list[str]
    json_files: list[str]
    overlay_path: str | None = None
    collect: str = DEFAULT_COLLECT


def resolve_bloodhound_executable() -> str | None:
    """Return path to bloodhound-python or compatible ``bloodhound`` shim."""
    return resolve_executable(["bloodhound-python", "bloodhound"])


def build_bloodhound_command(
    *,
    executable: str,
    domain: str,
    username: str,
    cred: Credential,
    dc_ip: str,
    output_dir: Path,
    collect: str = DEFAULT_COLLECT,
) -> list[str]:
    """Build argv for bloodhound-python without embedding secrets in logs."""
    user_arg = username
    if "@" not in user_arg and domain:
        user_arg = f"{username}@{domain}"

    cmd = [
        executable,
        "-d",
        domain,
        "-u",
        user_arg,
        "-ns",
        dc_ip,
        "-c",
        collect,
        "-op",
        str(output_dir / OUTPUT_PREFIX),
    ]

    if cred.cred_type == CredentialType.NTLM:
        secret = cred.secret.strip()
        if ":" in secret and len(secret.split(":")) >= 2:
            hash_arg = secret if secret.startswith(":") else f":{secret.split(':')[-1]}"
        else:
            hash_arg = f":{secret}"
        cmd.extend(["--hashes", hash_arg])
    elif cred.cred_type == CredentialType.KERBEROS:
        cmd.extend(["-k", "--no-pass"])
    else:
        cmd.extend(["-p", cred.secret])

    return cmd


def _list_collected_json(output_dir: Path) -> list[Path]:
    skip = {"bloodhound_overlay.json"}
    files: list[Path] = []
    for path in sorted(output_dir.glob("*.json")):
        if path.name in skip:
            continue
        files.append(path)
    return files


def run_bloodhound_collect(
    session: Session,
    *,
    cred_id: str | None = None,
    collect: str = DEFAULT_COLLECT,
) -> BloodhoundCollectResult:
    """Run bloodhound-python and rebuild the dashboard overlay artifact."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    from admapper.support.discovery import ensure_domain

    domain = ensure_domain(session, announce=False)
    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC IP — run start_unauth or set hosts first")

    cred = _pick_credential(session, cred_id)
    if not cred.secret:
        raise ValueError(f"credential {cred.id} has no secret")

    executable = resolve_bloodhound_executable()
    if not executable:
        raise RuntimeError(
            "bloodhound-python not found — install via pipx or use the bloodhound-ce branch"
        )

    ws_name = session.workspace.name
    output_dir = session.workspaces.path_for(ws_name) / "bloodhound"
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = build_bloodhound_command(
        executable=executable,
        domain=domain,
        username=cred.username,
        cred=cred,
        dc_ip=dc_ip,
        output_dir=output_dir,
        collect=collect or DEFAULT_COLLECT,
    )

    from admapper.support.provenance import Tool, print_ok
    from admapper.support.verbosity import print_phase

    print_phase(
        f"BloodHound collection ({collect or DEFAULT_COLLECT}) @ {dc_ip} → bloodhound/"
    )
    env = os.environ.copy()
    if cred.cred_type == CredentialType.KERBEROS and cred.secret:
        env.setdefault("KRB5CCNAME", cred.secret)

    proc = subprocess.run(
        cmd,
        cwd=str(output_dir),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    combined = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
    for line in combined.splitlines():
        print(line)

    if proc.returncode != 0:
        raise RuntimeError(f"bloodhound-python exited with code {proc.returncode}")

    json_files = [p.name for p in _list_collected_json(output_dir)]
    if not json_files:
        raise RuntimeError(
            "bloodhound-python produced no JSON in bloodhound/ — "
            "check credentials and DC reachability"
        )

    from admapper.dashboard.bloodhound_overlay import build_and_save_overlay

    overlay_path = build_and_save_overlay(output_dir.parent, domain=domain)
    print_ok(
        f"BloodHound overlay → bloodhound_overlay.json ({len(json_files)} source file(s))",
        source=Tool.BLOODHOUND,
    )

    manifest = output_dir / "collection_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "collected_at": datetime.now(UTC).isoformat(),
                "collect": collect or DEFAULT_COLLECT,
                "domain": domain,
                "dc_ip": dc_ip,
                "credential_id": cred.id,
                "username": cred.username,
                "json_files": json_files,
                "overlay": str(overlay_path.name) if overlay_path else None,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return BloodhoundCollectResult(
        output_dir=output_dir,
        command=cmd,
        json_files=json_files,
        overlay_path=str(overlay_path) if overlay_path else None,
        collect=collect or DEFAULT_COLLECT,
    )
