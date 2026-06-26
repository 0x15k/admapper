"""OPSEC Profiles — operational security noise control.

Three built-in profiles control the aggressiveness and noise level
of every ADMapper operation:

  STEALTH  — minimum footprint: delays, no spray, read-only, explicit confirms
  NORMAL   — balanced defaults (current behaviour)
  LAB      — no delays, no confirmations, maximum aggression (assessment/lab use)

Usage in CLI:
  admapper opsec stealth   # set profile
  admapper opsec show      # show current profile + settings

Usage in code:
  from admapper.core.opsec import get_opsec, OpsecProfile
  opsec = get_opsec(session)
  opsec.sleep_between_requests()     # auto-delays in STEALTH
  if opsec.require_confirm("spray"): # gate noisy ops
      ...
"""
from __future__ import annotations

import json
import time
import random
from enum import StrEnum
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from admapper.core.session import Session


class OpsecProfile(StrEnum):
    STEALTH = "stealth"
    NORMAL = "normal"
    LAB = "lab"


@dataclass
class OpsecSettings:
    """Runtime settings derived from the active OPSEC profile."""

    profile: OpsecProfile = OpsecProfile.NORMAL

    # Delays (seconds)
    request_delay_min: float = 0.0
    request_delay_max: float = 0.0

    # Feature gates
    allow_spray: bool = True
    allow_roast: bool = True
    allow_coerce: bool = True
    allow_dcsync: bool = True

    # Confirmation thresholds
    confirm_spray: bool = True
    confirm_coerce: bool = True
    confirm_dcsync: bool = True
    confirm_exploit: bool = True

    # LDAP paging (smaller = less noise)
    ldap_page_size: int = 1000

    def sleep_between_requests(self) -> None:
        """Insert an OPSEC-appropriate delay between network operations."""
        if self.request_delay_max <= 0:
            return
        delay = random.uniform(self.request_delay_min, self.request_delay_max)
        time.sleep(delay)

    def require_confirm(self, operation: str) -> bool:
        """Return True if this operation requires user confirmation.

        Always returns False in LAB mode (unattended).
        """
        if self.profile == OpsecProfile.LAB:
            return False
        mapping = {
            "spray": self.confirm_spray,
            "coerce": self.confirm_coerce,
            "dcsync": self.confirm_dcsync,
            "exploit": self.confirm_exploit,
        }
        return mapping.get(operation.lower(), True)

    def to_dict(self) -> dict:
        return {
            "profile": self.profile.value,
            "request_delay_min": self.request_delay_min,
            "request_delay_max": self.request_delay_max,
            "allow_spray": self.allow_spray,
            "allow_roast": self.allow_roast,
            "allow_coerce": self.allow_coerce,
            "allow_dcsync": self.allow_dcsync,
            "confirm_spray": self.confirm_spray,
            "confirm_coerce": self.confirm_coerce,
            "confirm_dcsync": self.confirm_dcsync,
            "confirm_exploit": self.confirm_exploit,
            "ldap_page_size": self.ldap_page_size,
        }


_PROFILES: dict[OpsecProfile, OpsecSettings] = {
    OpsecProfile.STEALTH: OpsecSettings(
        profile=OpsecProfile.STEALTH,
        request_delay_min=3.0,
        request_delay_max=10.0,
        allow_spray=False,   # Spray disabled in stealth (online attack)
        allow_roast=True,    # Roasting is read-only (pre-auth requests)
        allow_coerce=False,  # No coercion in stealth (very noisy)
        allow_dcsync=True,   # DCSync only if already DA
        confirm_spray=True,
        confirm_coerce=True,
        confirm_dcsync=True,
        confirm_exploit=True,
        ldap_page_size=200,
    ),
    OpsecProfile.NORMAL: OpsecSettings(
        profile=OpsecProfile.NORMAL,
        request_delay_min=0.0,
        request_delay_max=0.5,
        allow_spray=True,
        allow_roast=True,
        allow_coerce=True,
        allow_dcsync=True,
        confirm_spray=True,
        confirm_coerce=True,
        confirm_dcsync=True,
        confirm_exploit=True,
        ldap_page_size=1000,
    ),
    OpsecProfile.LAB: OpsecSettings(
        profile=OpsecProfile.LAB,
        request_delay_min=0.0,
        request_delay_max=0.0,
        allow_spray=True,
        allow_roast=True,
        allow_coerce=True,
        allow_dcsync=True,
        confirm_spray=False,
        confirm_coerce=False,
        confirm_dcsync=False,
        confirm_exploit=False,
        ldap_page_size=1000,
    ),
}

# Process-level override (used by tests and CLI flags)
_ACTIVE_PROFILE: OpsecProfile | None = None


def set_global_profile(profile: OpsecProfile) -> None:
    """Override the active OPSEC profile for this process."""
    global _ACTIVE_PROFILE
    _ACTIVE_PROFILE = profile


def get_opsec(session: "Session | None" = None) -> OpsecSettings:
    """Return the active OpsecSettings for the session.

    Priority: process override → workspace state → NORMAL default.
    """
    if _ACTIVE_PROFILE is not None:
        return _PROFILES[_ACTIVE_PROFILE]

    if session is not None and session.workspace is not None:
        profile = _load_workspace_profile(
            session.workspaces.path_for(session.workspace.name)
        )
        if profile is not None:
            return _PROFILES[profile]

    return _PROFILES[OpsecProfile.NORMAL]


def save_workspace_profile(ws_path: Path, profile: OpsecProfile) -> None:
    """Persist the OPSEC profile in workspace state.json."""
    state_path = ws_path / "state.json"
    try:
        data: dict = {}
        if state_path.is_file():
            data = json.loads(state_path.read_text(encoding="utf-8"))
        data["opsec_profile"] = profile.value
        state_path.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except Exception:
        pass


def _load_workspace_profile(ws_path: Path) -> OpsecProfile | None:
    state_path = ws_path / "state.json"
    if not state_path.is_file():
        return None
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        raw = str(data.get("opsec_profile") or "")
        return OpsecProfile(raw)
    except (ValueError, KeyError, Exception):
        return None


def print_opsec_status(session: "Session | None" = None) -> None:
    """Print the current OPSEC profile and key settings."""
    from admapper.core.output import print_table, print_info

    settings = get_opsec(session)
    print_info(f"OPSEC profile: {settings.profile.upper()}")
    rows = [
        ["Request delay", f"{settings.request_delay_min:.0f}–{settings.request_delay_max:.0f}s"],
        ["Password spray", "allowed" if settings.allow_spray else "BLOCKED"],
        ["Coercion", "allowed" if settings.allow_coerce else "BLOCKED"],
        ["DCSync", "allowed" if settings.allow_dcsync else "blocked"],
        ["Confirm spray?", "yes" if settings.confirm_spray else "no (auto)"],
        ["Confirm coerce?", "yes" if settings.confirm_coerce else "no (auto)"],
        ["LDAP page size", str(settings.ldap_page_size)],
    ]
    print_table(f"OPSEC — {settings.profile}", ["setting", "value"], rows)
