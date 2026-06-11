from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

UAC_DONT_REQ_PREAUTH = 0x400000
UAC_ACCOUNTDISABLE = 0x000002
UAC_PASSWD_NOTREQD = 0x000020


@dataclass
class UserRecord:
    """Unified AD user from one or more enumeration sources."""

    username: str
    sources: list[str] = field(default_factory=list)
    rid: int | None = None
    description: str | None = None
    dn: str | None = None
    uac: int | None = None
    spns: list[str] = field(default_factory=list)
    asrep_roastable: bool = False
    kerberoastable: bool = False
    password_not_required: bool = False
    enabled: bool = True
    bad_pwd_count: int | None = None
    lockout_time: int | None = None

    @property
    def is_machine_account(self) -> bool:
        return self.username.endswith("$")

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "sources": list(self.sources),
            "rid": self.rid,
            "description": self.description,
            "dn": self.dn,
            "uac": self.uac,
            "spns": list(self.spns),
            "asrep_roastable": self.asrep_roastable,
            "kerberoastable": self.kerberoastable,
            "password_not_required": self.password_not_required,
            "enabled": self.enabled,
            "bad_pwd_count": self.bad_pwd_count,
            "lockout_time": self.lockout_time,
            "is_machine_account": self.is_machine_account,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserRecord:
        return cls(
            username=str(data.get("username", "")),
            sources=list(data.get("sources") or []),
            rid=data.get("rid"),
            description=data.get("description"),
            dn=data.get("dn"),
            uac=data.get("uac"),
            spns=list(data.get("spns") or []),
            asrep_roastable=bool(data.get("asrep_roastable")),
            kerberoastable=bool(data.get("kerberoastable")),
            password_not_required=bool(data.get("password_not_required")),
            enabled=bool(data.get("enabled", True)),
            bad_pwd_count=data.get("bad_pwd_count"),
            lockout_time=data.get("lockout_time"),
        )


def apply_uac_flags(user: UserRecord) -> UserRecord:
    """Derive roast/spray flags from userAccountControl and SPNs."""
    if user.uac is not None:
        user.asrep_roastable = bool(user.uac & UAC_DONT_REQ_PREAUTH)
        user.password_not_required = bool(user.uac & UAC_PASSWD_NOTREQD)
        user.enabled = not bool(user.uac & UAC_ACCOUNTDISABLE)
    if user.spns and not user.is_machine_account:
        user.kerberoastable = True
    return user
