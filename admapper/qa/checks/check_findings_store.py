#!/usr/bin/env python3
"""QA check for FindingsStore merge behaviour."""
from __future__ import annotations

import tempfile
from pathlib import Path

from admapper.core.findings import FindingsStore
from admapper.core.workspace import WorkspaceManager
from admapper.models.finding import Finding, FindingSeverity


def _assert(condition: bool, message: str) -> None:
    if not condition:
        print(f"[-] {message}")
        raise SystemExit(1)
    print(f"[+] {message}")


def main() -> None:
    print("[*] Checking findings store merge...")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        manager = WorkspaceManager(tmp_path)
        manager.create("qa-ws")
        store = FindingsStore(manager, "qa-ws")
        store.merge(
            [
                Finding(
                    key="ldap_anonymous",
                    title="LDAP anonymous bind enabled",
                    severity=FindingSeverity.MEDIUM,
                    source="ldap_probe",
                )
            ]
        )
        store.merge(
            [
                Finding(
                    key="ldap_anonymous",
                    title="LDAP anonymous bind enabled",
                    severity=FindingSeverity.HIGH,
                    source="ldap_probe",
                    detail="updated",
                )
            ]
        )
        findings = store.list()
        _assert(len(findings) == 1, "duplicate findings are merged by key")
        _assert(findings[0].severity == FindingSeverity.HIGH, "severity is updated on merge")
        _assert(findings[0].detail == "updated", "detail is updated on merge")

    print("[+] Findings store check passed")


if __name__ == "__main__":
    main()
