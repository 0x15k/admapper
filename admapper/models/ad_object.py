from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GroupRecord:
    name: str
    dn: str | None = None
    members: list[str] = field(default_factory=list)
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "dn": self.dn,
            "members": list(self.members),
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GroupRecord:
        return cls(
            name=str(data.get("name", "")),
            dn=data.get("dn"),
            members=list(data.get("members") or []),
            description=data.get("description"),
        )


@dataclass
class ComputerRecord:
    name: str
    dn: str | None = None
    dns_host: str | None = None
    operating_system: str | None = None
    enabled: bool = True
    unconstrained_delegation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "dn": self.dn,
            "dns_host": self.dns_host,
            "operating_system": self.operating_system,
            "enabled": self.enabled,
            "unconstrained_delegation": self.unconstrained_delegation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ComputerRecord:
        return cls(
            name=str(data.get("name", "")),
            dn=data.get("dn"),
            dns_host=data.get("dns_host"),
            operating_system=data.get("operating_system"),
            enabled=bool(data.get("enabled", True)),
            unconstrained_delegation=bool(data.get("unconstrained_delegation")),
        )


@dataclass
class OuRecord:
    name: str
    dn: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "dn": self.dn}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OuRecord:
        return cls(name=str(data.get("name", "")), dn=data.get("dn"))


@dataclass
class GpoRecord:
    name: str
    dn: str | None = None
    display_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "dn": self.dn, "display_name": self.display_name}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GpoRecord:
        return cls(
            name=str(data.get("name", "")),
            dn=data.get("dn"),
            display_name=data.get("display_name"),
        )


@dataclass
class DelegationRecord:
    object_name: str
    object_type: str
    delegation_type: str
    targets: list[str] = field(default_factory=list)
    dn: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_name": self.object_name,
            "object_type": self.object_type,
            "delegation_type": self.delegation_type,
            "targets": list(self.targets),
            "dn": self.dn,
        }


@dataclass
class TrustRecord:
    name: str
    flat_name: str | None = None
    direction: str | None = None
    trust_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "flat_name": self.flat_name,
            "direction": self.direction,
            "trust_type": self.trust_type,
        }


@dataclass
class AclAbuseFinding:
    right: str
    principal: str
    trustee_sid: str
    trustee_name: str
    target_dn: str
    target_name: str
    target_type: str
    severity: str
    mitre_id: str
    summary: str
    manual_commands: list[str] = field(default_factory=list)
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "right": self.right,
            "principal": self.principal,
            "trustee_sid": self.trustee_sid,
            "trustee_name": self.trustee_name,
            "target_dn": self.target_dn,
            "target_name": self.target_name,
            "target_type": self.target_type,
            "severity": self.severity,
            "mitre_id": self.mitre_id,
            "summary": self.summary,
            "manual_commands": list(self.manual_commands),
        }


@dataclass
class GppCredential:
    user: str
    password: str
    source_file: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "user": self.user,
            "password": self.password,
            "source_file": self.source_file,
        }
