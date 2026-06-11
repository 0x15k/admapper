from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from uuid import uuid4


class CredentialType(StrEnum):
    PASSWORD = "password"
    NTLM = "ntlm"
    KERBEROS = "kerberos"


class CredentialStatus(StrEnum):
    UNVERIFIED = "unverified"
    VALID = "valid"
    INVALID = "invalid"


@dataclass
class Credential:
    """A domain credential tracked in the workspace."""

    username: str
    secret: str
    cred_type: CredentialType = CredentialType.PASSWORD
    domain: str | None = None
    status: CredentialStatus = CredentialStatus.UNVERIFIED
    source: str = "manual"
    id: str = field(default_factory=lambda: uuid4().hex[:12])

    def to_dict(self, *, include_secret: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "username": self.username,
            "type": self.cred_type.value,
            "domain": self.domain,
            "status": self.status.value,
            "source": self.source,
        }
        if include_secret:
            payload["secret"] = self.secret
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Credential:
        cred_type_raw = str(data.get("type", CredentialType.PASSWORD.value))
        status_raw = str(data.get("status", CredentialStatus.UNVERIFIED.value))
        try:
            cred_type = CredentialType(cred_type_raw)
        except ValueError:
            cred_type = CredentialType.PASSWORD
        try:
            status = CredentialStatus(status_raw)
        except ValueError:
            status = CredentialStatus.UNVERIFIED
        return cls(
            id=str(data.get("id") or uuid4().hex[:12]),
            username=str(data.get("username", "")),
            secret=str(data.get("secret", "")),
            cred_type=cred_type,
            domain=data.get("domain"),
            status=status,
            source=str(data.get("source") or "manual"),
        )

    def display_user(self) -> str:
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username
