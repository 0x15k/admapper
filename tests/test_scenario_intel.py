from admapper.postex.loot_intel import LootIntelResult
from admapper.postex.scenario_intel import (
    LOGGING_UPDATE_MONITOR,
    detect_scenario,
    scenario_to_finding,
    scenario_to_hijack_intel,
)


def test_detect_logging_update_monitor() -> None:
    loot = LootIntelResult(
        zip_dll_refs=["Logs/monitor.log: Settings_Update.zip at UpdateMonitor"],
        dll_hijack_refs=["settings_update.dll"],
    )
    monitor = "No updates found locally: C:\\ProgramData\\UpdateMonitor\\Settings_Update.zip."
    scenario = detect_scenario("logging.htb", loot=loot, monitor_log=monitor)
    assert scenario is not None
    assert scenario.run_as == "jaylee.clifton"
    assert scenario.drop_path == r"C:\ProgramData\UpdateMonitor"


def test_detect_scenario_requires_remote_corpus() -> None:
    loot = LootIntelResult(zip_dll_refs=["Settings_Update.zip"])
    assert detect_scenario("logging.htb", loot=loot) is None


def test_scenario_to_finding() -> None:
    intel = scenario_to_hijack_intel(LOGGING_UPDATE_MONITOR)
    assert intel.payload_zip == "Settings_Update.zip"
    finding = scenario_to_finding(LOGGING_UPDATE_MONITOR)
    assert finding.run_as_user == "jaylee.clifton"
    assert "UpdateMonitor.exe" in finding.executable
