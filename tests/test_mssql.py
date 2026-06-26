import json
from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.users import UsersStore
from admapper.core.workspace import WorkspaceManager
from admapper.models.credential import CredentialStatus
from admapper.models.host import HostRecord
from admapper.models.mssql_op import MssqlInstance
from admapper.models.user import UserRecord
from admapper.mssql.analyze import build_mssql_opportunities, run_mssql_analysis
from admapper.mssql.discover import discover_mssql_instances
from admapper.mssql.enum import MssqlEnumResult


def test_discover_mssql_instances_from_hosts_and_spns(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")

    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.5", open_ports=[1433])]
    )
    UsersStore(manager, "lab").merge(
        [
            UserRecord(
                username="sqlsvc",
                spns=["MSSQLSvc/sql01.target.example:1433"],
            )
        ]
    )

    instances = discover_mssql_instances(session)
    hosts = {i.host for i in instances}
    assert "10.0.0.5" in hosts
    assert "sql01.target.example" in hosts


def test_build_mssql_opportunities_covers_phase15() -> None:
    instances = [
        MssqlInstance(host="sql01.target.example"),
        MssqlInstance(host="sql02.target.example"),
    ]
    enum_results = [
        MssqlEnumResult(
            host="sql01.target.example",
            login_ok=True,
            is_sysadmin=True,
            linked_servers=["REMOTE01"],
            trustworthy_databases=["appdb"],
            xp_cmdshell_enabled=True,
        ),
        MssqlEnumResult(host="sql02.target.example", login_ok=False, error="login failed"),
    ]

    ops = build_mssql_opportunities(
        instances,
        enum_results,
        context="target.example\\jsmith",
    )
    techniques = {o.technique for o in ops}
    assert "sql_access" in techniques
    assert "sql_admin" in techniques
    assert "impersonate" in techniques
    assert "linked_server" in techniques
    assert "trustworthy" in techniques
    assert "xp_cmdshell" in techniques


def test_run_mssql_analysis_writes_artifacts(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    session.workspace.owned_users = ["jsmith"]
    session.persist_workspace()

    HostsStore(manager, "lab").merge(
        [HostRecord(address="sql01.target.example", open_ports=[1433])]
    )
    cred = session.credentials.add("jsmith", "Secret123!", domain="target.example")
    session.credentials.mark_status(cred.id, CredentialStatus.VALID)

    mock_enum = MssqlEnumResult(
        host="sql01.target.example",
        login_ok=True,
        is_sysadmin=False,
        linked_servers=["LINKED01"],
    )

    with (
        patch("admapper.mssql.analyze.enumerate_mssql_instance", return_value=mock_enum),
        patch("admapper.mssql.analyze.print_manual_guide"),
    ):
        result = run_mssql_analysis(session)

    assert result.opportunities
    assert (tmp_path / "ws" / "lab" / "mssql_inventory.json").is_file()
    assert (tmp_path / "ws" / "lab" / "mssql_findings.json").is_file()

    findings = json.loads(
        (tmp_path / "ws" / "lab" / "mssql_findings.json").read_text(encoding="utf-8")
    )
    assert findings["finding_count"] == len(result.opportunities)
