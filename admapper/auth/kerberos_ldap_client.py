from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any

from admapper.support.platform import get_clock_skew, wrap_command_with_clock_skew


@dataclass
class _LdapAttr:
    value: str
    values: list[str]

    @property
    def raw_values(self) -> list[bytes]:
        return [v.encode("latin-1") for v in self.values]


@dataclass
class _LdapEntry:
    distinguishedName: _LdapAttr
    _attrs: dict[str, _LdapAttr] = field(default_factory=dict)

    def __getattr__(self, name: str) -> _LdapAttr | None:
        if name == "distinguishedName":
            return self.distinguishedName
        return self._attrs.get(name)


class KerberosLdapConnection:
    """ldap3-shaped connection backed by impacket Kerberos REPL."""

    def __init__(self, proc: subprocess.Popen[str]) -> None:
        self._proc = proc
        self.entries: list[_LdapEntry] = []

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("kerberos ldap repl not running")
        self._proc.stdin.write(json.dumps(payload) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            raise RuntimeError("kerberos ldap repl closed")
        return json.loads(line)

    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: Any = None,
        attributes: list[str] | None = None,
        *,
        controls: Any = None,
    ) -> bool:
        if controls is not None:
            dn = search_base
            result = self._request({"cmd": "fetch_sd", "dn": dn})
            if not result.get("ok"):
                self.entries = []
                return False
            import base64

            data = base64.b64decode(str(result["sd_b64"]))
            entry = _LdapEntry(
                distinguishedName=_LdapAttr(dn, [dn]),
                _attrs={
                    "nTSecurityDescriptor": _LdapAttr(
                        data.decode("latin-1", errors="replace"),
                        [data.decode("latin-1", errors="replace")],
                    )
                },
            )
            self.entries = [entry]
            return True

        result = self._request(
            {
                "cmd": "search",
                "base_dn": search_base,
                "filter": search_filter,
                "attributes": attributes or [],
            }
        )
        if not result.get("ok"):
            self.entries = []
            return False
        entries: list[_LdapEntry] = []
        for item in result.get("entries") or []:
            dn = str(item.get("dn", ""))
            attrs: dict[str, _LdapAttr] = {}
            for key, values in (item.get("attributes") or {}).items():
                vals = [str(v) for v in values]
                attr = _LdapAttr(vals[0] if vals else "", vals)
                attrs[key] = attr
                norm = key[:1].lower() + key[1:] if key else key
                if norm != key:
                    attrs[norm] = attr
            entries.append(
                _LdapEntry(
                    distinguishedName=_LdapAttr(dn, [dn]),
                    _attrs=attrs,
                )
            )
        self.entries = entries
        return True

    def close(self) -> None:
        try:
            self._request({"cmd": "quit"})
        except Exception:
            pass
        if self._proc.stdin:
            self._proc.stdin.close()
        self._proc.terminate()


@dataclass
class KerberosLdapRepl:
    conn: KerberosLdapConnection
    process: subprocess.Popen[str]
    base_dn: str

    def close(self) -> None:
        self.conn.close()


def start_kerberos_ldap_repl(
    host: str,
    user: str,
    password: str,
    domain: str,
    *,
    dc_ip: str | None = None,
    ldap_host: str | None = None,
    clock_skew: str | None = None,
) -> KerberosLdapRepl:
    cmd = [sys.executable, "-m", "admapper.auth.kerberos_ldap_repl"]
    skew = clock_skew or get_clock_skew()
    cmd = wrap_command_with_clock_skew(cmd, clock_skew=skew)
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    client = KerberosLdapConnection(proc)
    result = client._request(
        {
            "cmd": "bind",
            "host": host,
            "user": user,
            "password": password,
            "domain": domain,
            "dc_ip": dc_ip or host,
            "ldap_host": ldap_host or host,
        }
    )
    if not result.get("ok"):
        err = str(result.get("error", "kerberos ldap bind failed"))
        proc.terminate()
        raise RuntimeError(err)
    base_dn = str(result.get("base_dn") or "")
    return KerberosLdapRepl(conn=client, process=proc, base_dn=base_dn)
