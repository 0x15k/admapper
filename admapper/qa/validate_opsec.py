#!/usr/bin/env python3
"""QA validation for ADMapper OPSEC profiles.

Run with: python scripts/qa/validate_opsec.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

from admapper.core.opsec import (
    OpsecProfile,
    _PROFILES,
    _load_workspace_profile,
    save_workspace_profile,
)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        print(f"[-] {message}")
        sys.exit(1)
    print(f"[+] {message}")


def main() -> None:
    print("[*] Validating OPSEC profiles...")

    stealth = _PROFILES[OpsecProfile.STEALTH]
    _assert(stealth.allow_spray is False, "STEALTH disables spraying")
    _assert(stealth.allow_coerce is False, "STEALTH disables coercion")
    _assert(stealth.request_delay_min >= 1.0, "STEALTH has minimum delay")
    _assert(stealth.request_delay_max >= stealth.request_delay_min, "STEALTH delay range is valid")

    lab = _PROFILES[OpsecProfile.LAB]
    _assert(lab.request_delay_max == 0.0, "LAB has no delays")
    _assert(lab.require_confirm("spray") is False, "LAB skips spray confirmation")
    _assert(lab.require_confirm("coerce") is False, "LAB skips coerce confirmation")
    _assert(lab.require_confirm("dcsync") is False, "LAB skips dcsync confirmation")
    _assert(lab.require_confirm("some_unknown_op") is False, "LAB skips unknown op confirmation")

    normal = _PROFILES[OpsecProfile.NORMAL]
    _assert(normal.require_confirm("spray") is True, "NORMAL requires spray confirmation")
    _assert(normal.require_confirm("coerce") is True, "NORMAL requires coerce confirmation")
    _assert(normal.require_confirm("unknown_operation") is True, "NORMAL requires confirmation for unknown ops")

    calls: list[float] = []
    original_sleep = time.sleep
    time.sleep = lambda n: calls.append(n)
    try:
        _PROFILES[OpsecProfile.LAB].sleep_between_requests()
        _assert(calls == [], "LAB sleep is a no-op")

        calls.clear()
        _PROFILES[OpsecProfile.NORMAL].sleep_between_requests()
        _assert(all(c <= 0.5 for c in calls), "NORMAL sleep stays fast")

        calls.clear()
        _PROFILES[OpsecProfile.STEALTH].sleep_between_requests()
        _assert(len(calls) == 1, "STEALTH sleeps once")
        _assert(calls[0] >= 3.0, "STEALTH delay is at least 3 seconds")
    finally:
        time.sleep = original_sleep

    tmp_path = Path("/tmp/admapper_opsec_validate")
    tmp_path.mkdir(parents=True, exist_ok=True)
    state_file = tmp_path / "state.json"
    if state_file.exists():
        state_file.unlink()

    save_workspace_profile(tmp_path, OpsecProfile.STEALTH)
    _assert(_load_workspace_profile(tmp_path) == OpsecProfile.STEALTH, "Save/load STEALTH profile works")

    save_workspace_profile(tmp_path, OpsecProfile.LAB)
    save_workspace_profile(tmp_path, OpsecProfile.STEALTH)
    _assert(_load_workspace_profile(tmp_path) == OpsecProfile.STEALTH, "Overwrite profile works")

    state_file.unlink()
    _assert(_load_workspace_profile(tmp_path) is None, "Missing profile returns None")

    (tmp_path / "state.json").write_text(json.dumps({"opsec_profile": "ultra-secret"}), encoding="utf-8")
    _assert(_load_workspace_profile(tmp_path) is None, "Invalid profile returns None")
    (tmp_path / "state.json").unlink()

    print("[+] All OPSEC validations passed")


if __name__ == "__main__":
    main()
