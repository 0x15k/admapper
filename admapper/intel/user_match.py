"""Backward-compatible shim — prefer ``admapper.analysis.user_match``."""

from admapper.analysis.user_match import (  # noqa: F401
    MatchedUser,
    build_user_intel,
    refresh_workspace_intel,
    sync_loot_users,
)

__all__ = ["MatchedUser", "build_user_intel", "refresh_workspace_intel", "sync_loot_users"]
