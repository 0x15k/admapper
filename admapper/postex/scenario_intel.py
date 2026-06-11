"""Domain-specific post-ex intel when loot/remote parse is incomplete."""

from __future__ import annotations

import re
from dataclasses import dataclass

from admapper.postex.hijack_intel import HijackIntel
from admapper.postex.loot_intel import LootIntelResult
from admapper.postex.task_hijack import TaskHijackFinding


@dataclass(frozen=True)
class ScenarioHijack:
    """Canonical DLL-hijack + escalation context for a known lab pattern."""

    domain: str
    task_name: str
    run_as: str
    executable: str
    arguments: str
    drop_path: str
    payload_zip: str
    payload_dll: str
    monitor_log_path: str
    next_human: str = ""
    next_chain: str = ""


# HTB Logging — UpdateMonitor scheduled task → jaylee.clifton → UpdateSrv / WSUS → DA
LOGGING_UPDATE_MONITOR = ScenarioHijack(
    domain="logging.htb",
    task_name="Update Check",
    run_as="jaylee.clifton",
    executable=r"C:\Program Files\UpdateMonitor\UpdateMonitor.exe",
    arguments=r"checks C:\ProgramData\UpdateMonitor\Settings_Update.zip → settings_update.dll",
    drop_path=r"C:\ProgramData\UpdateMonitor",
    payload_zip="Settings_Update.zip",
    payload_dll="settings_update.dll",
    monitor_log_path=r"C:\ProgramData\UpdateMonitor\Logs\monitor.log",
    next_human="jaylee.clifton",
    next_chain="UpdateSrv (Server Auth) → WSUS spoof → DA",
)


def _corpus(
    *,
    domain: str,
    loot: LootIntelResult | None,
    monitor_log: str,
    com_out: str,
) -> str:
    parts = [domain, monitor_log, com_out]
    if loot:
        parts.extend(loot.zip_dll_refs)
        parts.extend(loot.dll_hijack_refs)
        for hint in loot.task_hints:
            parts.append(hint.line)
            parts.append(hint.task_name)
    return "\n".join(parts).lower()


def detect_scenario(
    domain: str,
    *,
    loot: LootIntelResult | None = None,
    monitor_log: str = "",
    com_out: str = "",
) -> ScenarioHijack | None:
    """Match known engagement patterns (UpdateMonitor / Settings_Update.zip)."""
    text = _corpus(domain=domain, loot=loot, monitor_log=monitor_log, com_out=com_out)
    if not text.strip():
        return None

    has_update_monitor = bool(
        re.search(r"updatemonitor|settings_update|update\s*check|updatesrv", text, re.I)
    )
    has_jaylee = "jaylee" in text or "jaylee.clifton" in text
    has_remote = bool(monitor_log.strip() or com_out.strip())

    if not has_update_monitor or not has_remote:
        return None
    if has_jaylee or "settings_update" in text:
        return LOGGING_UPDATE_MONITOR
    return None


def scenario_to_hijack_intel(scenario: ScenarioHijack) -> HijackIntel:
    return HijackIntel(
        payload_zip=scenario.payload_zip,
        payload_dll=scenario.payload_dll,
        drop_path=scenario.drop_path,
        monitor_log_path=scenario.monitor_log_path,
        task_name_hint=scenario.task_name,
        com_task_filter=scenario.task_name.split()[0],
    )


def scenario_to_finding(
    scenario: ScenarioHijack,
    *,
    writable: bool = False,
    evidence: list[str] | None = None,
) -> TaskHijackFinding:
    ev = list(evidence or [])
    ev.append(f"scenario: {scenario.domain} UpdateMonitor → {scenario.next_human}")
    return TaskHijackFinding(
        task_name=scenario.task_name,
        run_as_user=scenario.run_as,
        executable=scenario.executable,
        arguments=scenario.arguments,
        drop_path=scenario.drop_path,
        payload_zip=scenario.payload_zip,
        payload_dll=scenario.payload_dll,
        writable=writable,
        target_arch="x86",
        evidence=ev,
        severity="critical" if writable else "high",
    )
