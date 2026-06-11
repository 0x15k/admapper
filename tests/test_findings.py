from pathlib import Path

from admapper.core.findings import FindingsStore
from admapper.core.workspace import WorkspaceManager
from admapper.models.finding import Finding, FindingSeverity


def test_findings_merge_by_key(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path)
    manager.create("lab")
    store = FindingsStore(manager, "lab")
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
    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.HIGH
    assert findings[0].detail == "updated"
