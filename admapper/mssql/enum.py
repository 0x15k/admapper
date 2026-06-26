from __future__ import annotations

from dataclasses import dataclass, field

from admapper.support.platform import tool_install_hint
from admapper.models.credential import Credential, CredentialType
from admapper.models.mssql_op import MssqlInstance


@dataclass
class MssqlEnumResult:
    host: str
    login_ok: bool = False
    is_sysadmin: bool = False
    linked_servers: list[str] = field(default_factory=list)
    trustworthy_databases: list[str] = field(default_factory=list)
    xp_cmdshell_enabled: bool | None = None
    error: str | None = None


def _row_values(row: object) -> list[str]:
    if isinstance(row, dict):
        return [str(v) for v in row.values()]
    if isinstance(row, (list, tuple)):
        return [str(c) for c in row]
    return [str(row)]


def _query_rows(ms_sql, sql: str) -> list[list[str]]:
    result = ms_sql.sql_query(sql)
    rows = result if result else getattr(ms_sql, "rows", [])
    return [_row_values(row) for row in rows]


def enumerate_mssql_instance(
    instance: MssqlInstance,
    cred: Credential,
    domain: str,
) -> MssqlEnumResult:
    """Live MSSQL enum when impacket is available and cred is password-based."""
    result = MssqlEnumResult(host=instance.host)
    if cred.cred_type != CredentialType.PASSWORD:
        result.error = "MSSQL enum requires password credential"
        return result

    try:
        from impacket import tds
    except ImportError:
        result.error = f"impacket not installed — {tool_install_hint('impacket')}"
        return result

    try:
        ms_sql = tds.MSSQL(instance.host, instance.port, instance.host)
        ms_sql.connect()
        ok = ms_sql.login(None, cred.username, cred.secret, domain, None, True)
        if not ok:
            result.error = "MSSQL login failed"
            ms_sql.disconnect()
            return result
        result.login_ok = True

        admin_rows = _query_rows(
            ms_sql,
            "SELECT IS_SRVROLEMEMBER('sysadmin')",
        )
        if admin_rows and admin_rows[0][0] in {"1", "True", "true"}:
            result.is_sysadmin = True

        for row in _query_rows(
            ms_sql,
            "SELECT name FROM sys.servers WHERE is_linked = 1",
        ):
            if row:
                result.linked_servers.append(row[0])

        for row in _query_rows(
            ms_sql,
            "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1",
        ):
            if row:
                result.trustworthy_databases.append(row[0])

        xp_rows = _query_rows(
            ms_sql,
            "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'",
        )
        if xp_rows:
            result.xp_cmdshell_enabled = xp_rows[0][0] in {"1", "True", "true"}

        ms_sql.disconnect()
    except Exception as exc:
        result.error = str(exc)
    return result
