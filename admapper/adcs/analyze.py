from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from admapper.acl.enum import resolve_principal_context
from admapper.adcs.acl_detect import detect_owned_adcs_abuse
from admapper.adcs.certipy import certipy_install_hint
from admapper.adcs.detect import detect_esc_vulnerabilities
from admapper.adcs.enum import enumerate_adcs
from admapper.auth.ldap_session import open_ldap_session
from admapper.creds.common import pick_dc_ip
from admapper.guides.render import print_manual_guide
from admapper.models.adcs import AdcsFinding
from admapper.models.credential import Credential, CredentialStatus
from admapper.support.output import print_info, print_success, print_table, print_warning
from admapper.support.platform import resolve_certipy

if TYPE_CHECKING:
    from admapper.support.session import Session


@dataclass
class AdcsAnalysisResult:
    findings: list[AdcsFinding] = field(default_factory=list)
    findings_path: str | None = None
    inventory_path: str | None = None
    errors: list[str] = field(default_factory=list)


def _pick_credential(session: Session, cred_id: str | None) -> Credential:
    store = session.credentials
    if store is None:
        raise RuntimeError("credential store unavailable")
    creds = store.list()
    if not creds:
        raise ValueError("no credentials — run start_auth or creds add")

    if cred_id:
        cred = next((c for c in creds if c.id == cred_id), None)
        if cred is None:
            raise ValueError(f"credential not found: {cred_id}")
        return cred

    for preferred in (CredentialStatus.VALID, CredentialStatus.UNVERIFIED):
        for cred in creds:
            if cred.status == preferred and cred.secret:
                return cred
    raise ValueError("no usable credential for AD CS enum")


def _build_group_enroll_hints(
    principals: list,
    templates: list,
) -> dict[str, list[str]]:
    """Infer enrollment only when template SD shows enroll ACE for a principal group SID."""
    hints: dict[str, list[str]] = {}
    for template in templates:
        if template.low_priv_enrollment:
            continue
        enroll_sids: set[str] = set()
        for ace_dict in template.security_aces or []:
            rights = list(ace_dict.get("rights") or [])
            sid = str(ace_dict.get("trustee_sid") or "")
            if sid and ("enroll" in rights or "genericall" in rights):
                enroll_sids.add(sid)
        if not enroll_sids:
            continue
        for principal in principals:
            if not enroll_sids.intersection(principal.all_sids):
                continue
            bucket = hints.setdefault(principal.username, set())
            bucket.add(template.name)
    return {user: sorted(names) for user, names in hints.items()}


def run_adcs_analysis(session: Session, *, cred_id: str | None = None) -> AdcsAnalysisResult:
    """Phase 12 — enumerate AD CS and detect ESC vulnerabilities."""
    if session.workspace is None:
        raise RuntimeError("no active workspace")

    domain = session.workspace.domain
    if not domain:
        raise ValueError("set domain <fqdn> before adcs")

    dc_ip = pick_dc_ip(session)
    if not dc_ip:
        raise ValueError("no DC — run start_unauth first")

    cred = _pick_credential(session, cred_id)
    ws_name = session.workspace.name
    ws_path = session.workspaces.path_for(ws_name)

    print_info(f"Phase 12 — AD CS enumeration @ {dc_ip} as {cred.display_user()}")

    ldap_session, err = open_ldap_session(dc_ip, cred, domain)
    if ldap_session is None:
        raise ValueError(err or "LDAP bind failed")

    enum_result = enumerate_adcs(ldap_session)
    if not enum_result.enrollment_services:
        print_warning("no AD CS enrollment services found in LDAP")
    else:
        print_success(
            f"found {len(enum_result.enrollment_services)} CA(s), "
            f"{len(enum_result.templates)} template(s)"
        )

    findings = detect_esc_vulnerabilities(
        templates=enum_result.templates,
        enrollment_services=enum_result.enrollment_services,
    )

    owned = list(session.workspace.owned_users or [])
    principals = []
    for username in owned:
        if username.endswith("$") or ":" in username:
            continue
        try:
            ctx = resolve_principal_context(ldap_session, username)
        except Exception as exc:
            print_warning(f"principal context {username}: {exc}")
            continue
        if ctx:
            principals.append(ctx)
            print_info(f"AD CS principal context: {username} (+ {len(ctx.group_sids)} groups)")

    if principals:
        owned_findings = detect_owned_adcs_abuse(
            templates=enum_result.templates,
            enrollment_services=enum_result.enrollment_services,
            principals=principals,
            domain=domain,
            dc_ip=dc_ip,
            group_enroll_hints=_build_group_enroll_hints(principals, enum_result.templates),
        )
        findings.extend(owned_findings)
        if owned_findings:
            print_success(
                f"owned-principal AD CS abuse: {len(owned_findings)} finding(s) "
                f"for {', '.join(p.username for p in principals[:3])}"
            )

    # Validate CA permissions for Golden Certificate severity
    has_ca_admin_rights = False
    principal_sids_set = set()
    for principal in principals:
        principal_sids_set.update(principal.all_sids)

    for service in enum_result.enrollment_services:
        for ace_dict in service.security_aces or []:
            sid = str(ace_dict.get("trustee_sid") or "")
            rights = list(ace_dict.get("rights") or [])
            if sid in principal_sids_set:
                if any(r in rights for r in ("manage_ca", "manage_certificates", "genericall")):
                    has_ca_admin_rights = True
                    break
        if has_ca_admin_rights:
            break

    for f in findings:
        if f.esc == "golden_cert":
            if has_ca_admin_rights:
                f.severity = "critical"
                f.prerequisites_met = True
            else:
                f.severity = "info"
                f.prerequisites_met = False

    certipy = resolve_certipy()
    if certipy:
        print_info(f"certipy available: {certipy}")
    else:
        print_warning(f"certipy not on PATH — {certipy_install_hint()}")
    for idx, finding in enumerate(findings, start=1):
        finding.id = f"adcs-{idx:03d}"

    result = AdcsAnalysisResult(
        findings=findings,
        errors=enum_result.errors,
    )

    adcs_inv_path = ws_path / "adcs_inventory.json"
    adcs_inv_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "dc_ip": dc_ip,
                "enrollment_services": [s.to_dict() for s in enum_result.enrollment_services],
                "templates": [t.to_dict() for t in enum_result.templates],
                "errors": enum_result.errors,
                "certipy_hint": certipy_install_hint(),
                "certipy_available": bool(certipy),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    result.inventory_path = str(adcs_inv_path)

    findings_path = ws_path / "adcs_findings.json"
    findings_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "finding_count": len(findings),
                "findings": [f.to_dict() for f in findings],
                "errors": enum_result.errors,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    result.findings_path = str(findings_path)

    if findings:
        rows = [[f.id, f.esc, f.template or "", f.ca_name or "", f.severity] for f in findings[:20]]
        print_table("AD CS findings", ["id", "esc", "template", "ca", "severity"], rows)
    else:
        print_warning("no ESC findings — AD CS may be hardened or ACLs restrict enum")

    print_success("AD CS inventory saved → adcs_inventory.json")
    print_success("AD CS findings saved → adcs_findings.json")
    print_manual_guide("adcs_esc", session=session)
    return result


def get_adcs_finding(session: Session, finding_id: str) -> dict[str, Any] | None:
    if session.workspace is None:
        raise RuntimeError("no active workspace")
    path = session.workspaces.path_for(session.workspace.name) / "adcs_findings.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data.get("findings", []):
        if str(item.get("id")) == finding_id:
            return item
    return None
