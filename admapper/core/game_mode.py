"""Game UI mode — no interactive sudo from browser-driven subprocesses."""

from __future__ import annotations

import os

GAME_MODE_ENV = "ADMAPPER_GAME_MODE"


def is_game_mode() -> bool:
    return os.environ.get(GAME_MODE_ENV, "").strip().lower() in {"1", "true", "yes"}


def enable_game_mode() -> None:
    os.environ[GAME_MODE_ENV] = "1"


def game_subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env[GAME_MODE_ENV] = "1"
    return env


def effective_sync_clock(requested: bool) -> bool:
    """In game mode Kerberos uses libfaketime / workspace skew — never sudo sntp."""
    if is_game_mode():
        return False
    return requested


def effective_sync_hosts(requested: bool) -> bool:
    """In game mode show /etc/hosts hint in UI instead of sudo tee."""
    if is_game_mode():
        return False
    return requested
