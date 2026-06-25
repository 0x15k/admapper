from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EnrollmentServiceRecord:
    name: str
    dns_host: str | None = None
    display_name: str | None = None
    templates: list[str] = field(default_factory=list)
    web_enrollment: bool = False
    enrollment_flags: int | None = None
    security_aces: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "dns_host": self.dns_host,
            "display_name": self.display_name,
            "templates": list(self.templates),
            "web_enrollment": self.web_enrollment,
            "enrollment_flags": self.enrollment_flags,
            "security_aces": list(self.security_aces),
        }


@dataclass
class CertificateTemplateRecord:
    name: str
    display_name: str | None = None
    enrollment_flags: int = 0
    extended_key_usage: list[str] = field(default_factory=list)
    schema_version: int | None = None
    low_priv_enrollment: bool = False
    requires_manager_approval: bool = False
    enrollee_supplies_subject: bool = False
    security_aces: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "enrollment_flags": self.enrollment_flags,
            "extended_key_usage": list(self.extended_key_usage),
            "schema_version": self.schema_version,
            "low_priv_enrollment": self.low_priv_enrollment,
            "requires_manager_approval": self.requires_manager_approval,
            "enrollee_supplies_subject": self.enrollee_supplies_subject,
            "security_aces": list(self.security_aces),
        }


@dataclass
class AdcsFinding:
    esc: str
    title: str
    severity: str
    mitre_id: str
    template: str | None
    ca_name: str | None
    summary: str
    detail: str = ""
    manual_commands: list[str] = field(default_factory=list)
    id: str = ""
    principal: str | None = None
    prerequisites_met: bool = True
    cert_auth_viable: bool | None = None
    wsus_chain_step: bool | None = None
    eku_summary: str = ""
    requires_external_listener: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = {
            "id": self.id,
            "esc": self.esc,
            "title": self.title,
            "severity": self.severity,
            "mitre_id": self.mitre_id,
            "template": self.template,
            "ca_name": self.ca_name,
            "summary": self.summary,
            "detail": self.detail,
            "manual_commands": list(self.manual_commands),
            "principal": self.principal,
            "prerequisites_met": self.prerequisites_met,
        }
        if self.cert_auth_viable is not None:
            data["cert_auth_viable"] = self.cert_auth_viable
        if self.wsus_chain_step is not None:
            data["wsus_chain_step"] = self.wsus_chain_step
        if self.eku_summary:
            data["eku_summary"] = self.eku_summary
        return data
