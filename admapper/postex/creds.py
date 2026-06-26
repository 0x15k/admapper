from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from admapper.creds.common import pick_dc_ip, resolve_winrm_host_for_account
from admapper.models.credential import CredentialStatus, CredentialType

if TYPE_CHECKING:
    from admapper.support.session import Session


@dataclass(frozen=True)
class WinRMCred:
    username: str
    domain: str
    host: str
    nthash: str | None = None
    password: str | None = None
    source: str = ""

    @property
    def uses_nthash(self) -> bool:
        return bool(self.nthash)


def _machine_account(name: str) -> str:
    return name if name.endswith("$") else f"{name}$"


def _valid_nthash(value: str) -> bool:
    h = value.lower().strip()
    return len(h) == 32 and h.isalnum() and not h.startswith("aes128")


def _hash_from_exploit_log(ws_path, *, username: str | None = None) -> tuple[str, str] | None:
    log_path = ws_path / "exploit_log.json"
    if not log_path.is_file():
        return None
    try:
        data = json.loads(log_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    want = username.lower().rstrip("$") if username else None
    for item in data.get("new_hashes") or []:
        account = str(item.get("account", ""))
        nthash = str(item.get("nthash", ""))
        if not account.endswith("$") or not _valid_nthash(nthash):
            continue
        if want and account.lower().rstrip("$") != want:
            continue
        return account, nthash.lower()
    return None


def machine_hash_from_workspace(ws_path) -> tuple[str, str] | None:
    """Return (account, nthash) from workspace exploit_log (any machine account)."""
    return _hash_from_exploit_log(ws_path)


def _nthash_from_store(session: Session, username: str) -> str | None:
    if session.credentials is None:
        return None
    want = username.lower().rstrip("$")
    for cred in session.credentials.list():
        if cred.status != CredentialStatus.VALID:
            continue
        if cred.cred_type != CredentialType.NTLM or not cred.secret:
            continue
        if cred.username.lower().rstrip("$") != want:
            continue
        if _valid_nthash(cred.secret):
            return cred.secret.lower()
    return None


def _winrm_target_host(
    session: Session,
    *,
    ws_path,
    account: str,
    explicit_host: str | None,
) -> str:
    if explicit_host:
        return explicit_host.rstrip(".")
    domain = session.workspace.domain or ""  # type: ignore[union-attr]
    dc_ip = pick_dc_ip(session)
    if account.endswith("$"):
        return resolve_winrm_host_for_account(
            account,
            ws_path,
            domain,
            fallback_ip=dc_ip,
        )
    if dc_ip:
        return dc_ip
    raise ValueError("no target host — add DC to workspace hosts or pass --host")


def resolve_winrm_cred(
    session: Session,
    *,
    shell_user: str | None = None,
    cred_id: str | None = None,
    host: str | None = None,
) -> WinRMCred:
    """Resolve WinRM credentials from workspace state (scan, creds, exploit log)."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain or ""
    if not domain:
        raise ValueError("workspace domain not set")

    ws_path = session.workspaces.path_for(session.workspace.name)

    if cred_id and session.credentials is not None:
        cred = session.credentials.get(cred_id)
        if cred is None:
            raise ValueError(f"credential not found: {cred_id}")
        if cred.cred_type == CredentialType.NTLM and cred.secret and _valid_nthash(cred.secret):
            user = _machine_account(cred.username)
            return WinRMCred(
                username=user,
                domain=cred.domain or domain,
                host=_winrm_target_host(session, ws_path=ws_path, account=user, explicit_host=host),
                nthash=cred.secret.lower(),
                source=f"credentials:{cred_id}",
            )
        if cred.cred_type == CredentialType.PASSWORD and cred.secret:
            user = cred.username
            return WinRMCred(
                username=user,
                domain=cred.domain or domain,
                host=_winrm_target_host(session, ws_path=ws_path, account=user, explicit_host=host),
                password=cred.secret,
                source=f"credentials:{cred_id}",
            )
        raise ValueError(f"credential {cred_id} has no usable secret for WinRM")

    if shell_user:
        nthash = _nthash_from_store(session, shell_user)
        if not nthash:
            from_log = _hash_from_exploit_log(ws_path, username=shell_user)
            if from_log:
                account, nthash = from_log
                return WinRMCred(
                    username=account,
                    domain=domain,
                    host=_winrm_target_host(
                        session, ws_path=ws_path, account=account, explicit_host=host
                    ),
                    nthash=nthash,
                    source="exploit_log",
                )
        if nthash:
            user = _machine_account(shell_user)
            return WinRMCred(
                username=user,
                domain=domain,
                host=_winrm_target_host(session, ws_path=ws_path, account=user, explicit_host=host),
                nthash=nthash,
                source="credentials",
            )

    if session.credentials is not None:
        for cred in session.credentials.list():
            if cred.status != CredentialStatus.VALID:
                continue
            if cred.cred_type != CredentialType.NTLM or not cred.secret:
                continue
            if not cred.username.endswith("$"):
                continue
            if not _valid_nthash(cred.secret):
                continue
            return WinRMCred(
                username=cred.username,
                domain=cred.domain or domain,
                host=_winrm_target_host(
                    session, ws_path=ws_path, account=cred.username, explicit_host=host
                ),
                nthash=cred.secret.lower(),
                source="credentials:auto",
            )

    from_log = _hash_from_exploit_log(ws_path)
    if from_log:
        account, nthash = from_log
        return WinRMCred(
            username=account,
            domain=domain,
            host=_winrm_target_host(session, ws_path=ws_path, account=account, explicit_host=host),
            nthash=nthash,
            source="exploit_log:auto",
        )

    raise ValueError("no WinRM credential — add machine NTLM hash (creds add) or run exploit chain")
