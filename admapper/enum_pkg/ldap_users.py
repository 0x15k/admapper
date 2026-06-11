"""Shim — implementation moved to ``admapper.enumeration.ldap_users``."""

from admapper.enumeration.ldap_users import LdapUserEnumResult, enumerate_users_ldap

__all__ = ["LdapUserEnumResult", "enumerate_users_ldap"]
