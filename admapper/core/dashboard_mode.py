"""Dashboard mode — no interactive sudo from browser-driven subprocesses."""

from __future__ import annotations

import os

DASHBOARD_MODE_ENV = "ADMAPPER_DASHBOARD_MODE"


def is_dashboard_mode() -> bool:
    return os.environ.get(DASHBOARD_MODE_ENV, "").strip().lower() in {"1", "true", "yes"}


def enable_dashboard_mode() -> None:
    os.environ[DASHBOARD_MODE_ENV] = "1"


def dashboard_subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env[DASHBOARD_MODE_ENV] = "1"
    return env


def effective_sync_clock(requested: bool) -> bool:
    """In dashboard mode Kerberos uses libfaketime / workspace skew — never sudo sntp."""
    if is_dashboard_mode():
        return False
    return requested


def effective_sync_hosts(requested: bool) -> bool:
    """In dashboard mode show /etc/hosts hint in UI instead of sudo tee."""
    if is_dashboard_mode():
        return False
    return requested
