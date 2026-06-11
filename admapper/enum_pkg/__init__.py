"""Backward-compatible shim — prefer ``admapper.enumeration``."""

from admapper.enumeration import UserEnumResult, run_user_enumeration

__all__ = ["UserEnumResult", "run_user_enumeration"]
