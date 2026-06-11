from __future__ import annotations

from admapper.cves.catalog import cve_meta
from admapper.cves.os_parse import ParsedOs, parse_operating_system
from admapper.models.cve_finding import CveFinding, CveTarget

_CATALOG_RULES: list[tuple[str, str, str]] = [
    ("CVE-2020-1472", "zerologon", "Netlogon bypass on unpatched DC"),
    ("CVE-2021-42278", "nopac", "sAMAccountName spoof on unpatched DC"),
    ("CVE-2021-42287", "nopac", "sAMAccountName spoof TGT escalation"),
    ("CVE-2021-34527", "printnightmare", "Print Spooler RCE"),
    ("CVE-2017-0144", "eternalblue", "SMBv1 RCE (MS17-010)"),
]


def _finding(
    technique: str,
    *,
    target: CveTarget,
    detail: str,
    confidence: str = "medium",
    exploitable: bool = False,
    cve_ids: list[str] | None = None,
) -> CveFinding:
    meta = cve_meta(technique)
    ids = list(cve_ids or meta.cve_ids)
    return CveFinding(
        technique=technique,
        title=meta.title,
        severity=meta.severity,
        mitre_id=meta.mitre_id,
        cve_ids=ids,
        summary=meta.summary,
        target_host=target.host,
        detail=detail,
        confidence=confidence,
        exploitable=exploitable,
        manual_commands=list(meta.manual_commands),
    )


def _smb_reachable(target: CveTarget) -> bool:
    return 445 in (target.open_ports or []) or not target.open_ports


def _detect_nopac(target: CveTarget, parsed: ParsedOs | None) -> CveFinding | None:
    if not target.is_domain_controller:
        return None
    if parsed and not parsed.is_dc_candidate:
        return None
    os_hint = parsed.raw if parsed else "unknown OS"
    return _finding(
        "nopac",
        target=target,
        detail=f"DC candidate ({os_hint}) — verify MAQ and patches",
        confidence="medium" if parsed else "low",
    )


def _detect_zerologon(target: CveTarget, parsed: ParsedOs | None) -> CveFinding | None:
    if not target.is_domain_controller:
        return None
    if parsed and parsed.version not in {None, "2008r2", "2012", "2012r2", "2016", "2019"}:
        if parsed.version in {"2022"}:
            return None
    if not _smb_reachable(target):
        return None
    os_hint = parsed.raw if parsed else "unknown OS"
    return _finding(
        "zerologon",
        target=target,
        detail=f"DC with RPC/SMB ({os_hint}) — run exploit only with confirm",
        confidence="medium" if parsed else "low",
    )


def _detect_printnightmare(target: CveTarget, parsed: ParsedOs | None) -> CveFinding | None:
    if parsed and parsed.family == "workstation" and parsed.version in {"10", "11"}:
        return None
    if parsed and not parsed.is_server and parsed.family != "unknown":
        return None
    if not _smb_reachable(target):
        return None
    os_hint = parsed.raw if parsed else "Windows Server (unknown version)"
    return _finding(
        "printnightmare",
        target=target,
        detail=f"Spooler may be exposed on {os_hint}",
        confidence="low" if not parsed else "medium",
    )


def _detect_eternalblue(target: CveTarget, parsed: ParsedOs | None) -> CveFinding | None:
    if parsed and not parsed.is_legacy_smb:
        return None
    if parsed is None:
        return None
    if not _smb_reachable(target):
        return None
    return _finding(
        "eternalblue",
        target=target,
        detail=f"Legacy SMB host ({parsed.raw}) — verify MS17-010",
        confidence="high",
    )


def _catalog_entries(target: CveTarget, parsed: ParsedOs | None) -> list[CveFinding]:
    entries: list[CveFinding] = []
    applicable: set[str] = set()

    if target.is_domain_controller:
        applicable.update({"CVE-2020-1472", "CVE-2021-42278", "CVE-2021-42287"})
    if parsed and parsed.is_legacy_smb:
        applicable.add("CVE-2017-0144")
    if parsed and (parsed.is_server or target.is_domain_controller):
        applicable.add("CVE-2021-34527")

    for cve_id, technique, note in _CATALOG_RULES:
        if cve_id not in applicable:
            continue
        meta = cve_meta(technique)
        entries.append(
            CveFinding(
                technique="cve_catalog",
                title=f"{cve_id} on {target.host}",
                severity=meta.severity,
                mitre_id=meta.mitre_id,
                cve_ids=[cve_id],
                summary=note,
                target_host=target.host,
                detail=f"OS: {parsed.raw if parsed else 'unknown'}",
                confidence="medium",
                manual_commands=list(meta.manual_commands),
            )
        )
    return entries


def detect_cve_findings(
    targets: list[CveTarget],
    *,
    machine_account_quota: int | None = None,
) -> list[CveFinding]:
    """Phase 16.1–16.5 — static CVE detection from inventory intel."""
    findings: list[CveFinding] = []
    seen: set[tuple[str, str, str]] = set()

    def add(finding: CveFinding | None) -> None:
        if finding is None:
            return
        key = (finding.technique, finding.target_host.lower(), finding.detail)
        if key in seen:
            return
        seen.add(key)
        findings.append(finding)

    for target in targets:
        parsed = parse_operating_system(target.operating_system)

        nopac = _detect_nopac(target, parsed)
        if nopac and machine_account_quota == 0:
            nopac = None
        elif nopac and machine_account_quota is not None and machine_account_quota > 0:
            nopac.detail += f"; MAQ={machine_account_quota}"
            nopac.confidence = "high"
        add(nopac)
        add(_detect_zerologon(target, parsed))
        add(_detect_printnightmare(target, parsed))
        add(_detect_eternalblue(target, parsed))
        for entry in _catalog_entries(target, parsed):
            add(entry)

    for idx, finding in enumerate(findings, start=1):
        finding.id = f"cve-{idx:03d}"
    return findings
