from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


@dataclass
class AsRepHash:
    """Kerberos AS-REP hash in hashcat-compatible format."""

    username: str
    domain: str
    hashcat: str
    cracked_password: str | None = None
    id: str = field(default_factory=lambda: uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "domain": self.domain,
            "hashcat": self.hashcat,
            "cracked_password": self.cracked_password,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AsRepHash:
        return cls(
            id=str(data.get("id") or uuid4().hex[:12]),
            username=str(data.get("username", "")),
            domain=str(data.get("domain", "")),
            hashcat=str(data.get("hashcat", "")),
            cracked_password=data.get("cracked_password"),
        )


@dataclass
class TgsHash:
    """Kerberos TGS (Kerberoast) hash in hashcat-compatible format."""

    username: str
    domain: str
    hashcat: str
    spn: str | None = None
    cracked_password: str | None = None
    id: str = field(default_factory=lambda: uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "domain": self.domain,
            "spn": self.spn,
            "hashcat": self.hashcat,
            "cracked_password": self.cracked_password,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TgsHash:
        return cls(
            id=str(data.get("id") or uuid4().hex[:12]),
            username=str(data.get("username", "")),
            domain=str(data.get("domain", "")),
            hashcat=str(data.get("hashcat", "")),
            spn=data.get("spn"),
            cracked_password=data.get("cracked_password"),
        )
