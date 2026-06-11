"""Shim — implementation moved to ``admapper.enumeration``."""

from admapper.enumeration.ldap_users import enumerate_users_ldap
from admapper.enumeration.rid_cycle import cycle_rids
from admapper.enumeration.samr import enumerate_users_samr
from admapper.enumeration.scan import UserEnumResult, run_user_enumeration

__all__ = [
    "UserEnumResult",
    "cycle_rids",
    "enumerate_users_ldap",
    "enumerate_users_samr",
    "run_user_enumeration",
]
