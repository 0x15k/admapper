from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from admapper.support.workspace import WorkspaceManager


@dataclass
class QuickWin:
    key: str
    title: str
    severity: str
    detail: str
    mitre_id: str | None = None
    command_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "severity": self.severity,
            "detail": self.detail,
            "mitre_id": self.mitre_id,
            "command_hint": self.command_hint,
        }


def collect_quick_wins(
    workspace: WorkspaceManager,
    workspace_name: str,
) -> list[QuickWin]:
    """Phase 9.6 — surface easy credential / misconfig wins from workspace artefacts."""
    wins: list[QuickWin] = []
    base = workspace.path_for(workspace_name)

    inv_path = base / "auth_inventory.json"
    if inv_path.is_file():
        inv = json.loads(inv_path.read_text(encoding="utf-8"))
        for idx, gpp in enumerate(inv.get("gpp_credentials") or []):
            wins.append(
                QuickWin(
                    key=f"gpp_{idx}",
                    title="GPP password in SYSVOL",
                    severity="high",
                    detail=f"{gpp.get('user')}:{gpp.get('password')} ({gpp.get('source_file')})",
                    mitre_id="T1552.006",
                    command_hint="creds add <user> <password>",
                )
            )
        if inv.get("adcs_present"):
            wins.append(
                QuickWin(
                    key="adcs_present",
                    title="AD CS detected",
                    severity="medium",
                    detail="Certificate enrollment services found — check vulnerable templates",
                    mitre_id="T1649",
                    command_hint="guide auth_enum",
                )
            )

    users_path = base / "users.json"
    if users_path.is_file():
        users = json.loads(users_path.read_text(encoding="utf-8")).get("users", [])
        for user in users:
            if user.get("password_not_required"):
                wins.append(
                    QuickWin(
                        key=f"passnotreq_{user.get('username')}",
                        title=f"Password not required: {user.get('username')}",
                        severity="high",
                        detail="userAccountControl PASSWD_NOTREQD bit set",
                        mitre_id="T1078",
                        command_hint=f"spray '' {user.get('username')}",
                    )
                )
            if user.get("asrep_roastable"):
                wins.append(
                    QuickWin(
                        key=f"asrep_{user.get('username')}",
                        title=f"AS-REP roastable: {user.get('username')}",
                        severity="medium",
                        detail="DONT_REQ_PREAUTH — offline hash crack",
                        mitre_id="T1558.004",
                        command_hint=f"asreproast {user.get('username')}",
                    )
                )

    creds_path = base / "credentials.json"
    if creds_path.is_file():
        for cred in json.loads(creds_path.read_text(encoding="utf-8")).get("credentials", []):
            if cred.get("source") in {"spray", "asreproast", "kerberoast", "gpp"}:
                wins.append(
                    QuickWin(
                        key=f"cred_{cred.get('id')}",
                        title=f"Recovered credential: {cred.get('username')}",
                        severity="high",
                        detail=f"source={cred.get('source')}, status={cred.get('status')}",
                        mitre_id="T1078",
                        command_hint="creds verify <id> && start_auth",
                    )
                )

    return wins
