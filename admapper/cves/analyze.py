from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from admapper.creds.common import pick_dc_ip
from admapper.cves.detect import detect_cve_findings
from admapper.cves.discover import discover_cve_targets
from admapper.cves.enum_domain import enumerate_domain_cve_context
from admapper.guides.render import print_manual_guide
from admapper.models.credential import CredentialStatus
from admapper.models.cve_finding import CveFinding
from admapper.support.output import print_info, print_success, print_table, print_warning

if TYPE_CHECKING:
    from admapper.support.session import Session


def _load_json(path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _pick_credential(session: Session):

    store = session.credentials
    if store is None:
        return None
    creds = store.list()
    owned = {u.lower() for u in (session.workspace.owned_users if session.workspace else [])}
    for preferred in (CredentialStatus.VALID, CredentialStatus.UNVERIFIED):
        for cred in creds:
            if cred.status == preferred and cred.secret and cred.username.lower() in owned:
                return cred
    for preferred in (CredentialStatus.VALID, CredentialStatus.UNVERIFIED):
        for cred in creds:
            if cred.status == preferred and cred.secret:
                return cred
    return None


@dataclass
class CveAnalysisResult:
    findings: list[CveFinding] = field(default_factory=list)
    inventory_path: str | None = None
    findings_path: str | None = None
    errors: list[str] = field(default_factory=list)


def run_cve_analysis(session: Session) -> CveAnalysisResult:
    """Phase 16 — CVE detection and catalog for DCs and workstations."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before cves")

    ws_name = session.workspace.name
    ws_path = session.workspaces.path_for(ws_name)

    print_info("Phase 16 — CVE analysis")

    inventory = _load_json(ws_path / "auth_inventory.json")
    if inventory is None:
        print_warning("no auth_inventory.json — run start_auth for OS-enriched targets")

    targets = discover_cve_targets(session, inventory)
    if not targets:
        print_warning("no targets — run start_unauth and start_auth")
    else:
        print_success(f"discovered {len(targets)} CVE target(s)")

    maq: int | None = None
    errors: list[str] = []
    cred = _pick_credential(session)
    dc_ip = pick_dc_ip(session)
    if cred and dc_ip:
        print_info("reading domain MAQ for noPac detection")
        ctx = enumerate_domain_cve_context(cred, domain, dc_ip)
        maq = ctx.machine_account_quota
        if ctx.error:
            errors.append(ctx.error)
    elif not cred:
        print_warning("no credential — skipping LDAP MAQ (noPac confidence reduced)")

    findings = detect_cve_findings(targets, machine_account_quota=maq)
    analysis = CveAnalysisResult(findings=findings, errors=errors)

    inv_path = ws_path / "cve_inventory.json"
    inv_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "target_count": len(targets),
                "machine_account_quota": maq,
                "targets": [t.to_dict() for t in targets],
                "errors": errors,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    analysis.inventory_path = str(inv_path)

    findings_path = ws_path / "cve_findings.json"
    findings_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "finding_count": len(findings),
                "findings": [f.to_dict() for f in findings],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    analysis.findings_path = str(findings_path)

    if findings:
        rows = [
            [f.id, f.technique, f.target_host, f.severity, ", ".join(f.cve_ids[:2])]
            for f in findings[:20]
        ]
        print_table("CVE findings", ["id", "technique", "host", "severity", "cve"], rows)
    else:
        print_warning("no CVE findings — enrich inventory with start_auth")

    print_success("CVE inventory saved → cve_inventory.json")
    print_success("CVE findings saved → cve_findings.json")
    print_manual_guide("cves_exploit", session=session)
    return analysis


def get_cve_finding(session: Session, finding_id: str) -> dict[str, Any] | None:
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    path = session.workspaces.path_for(session.workspace.name) / "cve_findings.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data.get("findings", []):
        if str(item.get("id")) == finding_id:
            return item
    return None
