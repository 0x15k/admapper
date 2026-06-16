from __future__ import annotations

from impacket.ldap.ldaptypes import LDAP_SID

from admapper.acl.enum import _sid_from_attr, resolve_principal_context

CANON = "S-1-5-21-1004336348-1177238915-682003330-1107"


def _sid_bytes(canonical: str) -> bytes:
    sid = LDAP_SID()
    sid.fromCanonical(canonical)
    return sid.getData()


class _Ldap3Attr:
    """Mimics an ldap3 attribute exposing raw byte values."""

    def __init__(self, raw: bytes) -> None:
        self.raw_values = [raw]
        self.value = raw


class _KerberosAttr:
    """Mimics the Kerberos LDAP shim attribute (value/values, no raw_values)."""

    def __init__(self, value) -> None:
        self.value = value
        self.values = [value]


def test_sid_from_attr_none() -> None:
    assert _sid_from_attr(None) is None


def test_sid_from_attr_ldap3_raw_bytes() -> None:
    attr = _Ldap3Attr(_sid_bytes(CANON))
    assert _sid_from_attr(attr) == CANON


def test_sid_from_attr_kerberos_canonical_string() -> None:
    attr = _KerberosAttr(CANON)
    assert _sid_from_attr(attr) == CANON


def test_sid_from_attr_kerberos_raw_bytes() -> None:
    attr = _KerberosAttr(_sid_bytes(CANON))
    assert _sid_from_attr(attr) == CANON


class _Entry:
    def __init__(self, attrs: dict) -> None:
        self._attrs = attrs

    def __getattr__(self, name: str):
        try:
            return self.__dict__["_attrs"][name]
        except KeyError:
            return None


class _Conn:
    def __init__(self, entries: list) -> None:
        self._entries = entries

    def search(self, *args, **kwargs) -> bool:
        return True

    @property
    def entries(self) -> list:
        return self._entries


class _Session:
    def __init__(self, entries: list) -> None:
        self.conn = _Conn(entries)
        self.base_dn = "DC=lab,DC=htb"


def test_resolve_principal_context_kerberos_entry() -> None:
    """Regression: resolve_principal_context used `.raw_values`, which the
    Kerberos LDAP shim entry does not provide, raising AttributeError and
    aborting the whole ACL run for Protected Users / Kerberos-only auth."""
    entry = _Entry(
        {
            "distinguishedName": _KerberosAttr("CN=svc,DC=lab,DC=htb"),
            "objectSid": _KerberosAttr(CANON),
            "memberOf": _KerberosAttr([]),
        }
    )
    ctx = resolve_principal_context(_Session([entry]), "svc", member_of=[])
    assert ctx is not None
    assert ctx.user_sid == CANON
    assert ctx.username == "svc"
