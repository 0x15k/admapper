from admapper.core.compatibility import (
    SupportTier,
    distribution_summary,
    feature_matrix,
)


def test_feature_matrix_has_core_commands() -> None:
    commands = {item.command for item in feature_matrix()}
    assert "start_unauth" in commands
    assert "spray" in commands
    assert "admapper start" in commands


def test_core_features_use_core_tier() -> None:
    core_cmds = {"spray", "start_unauth", "admapper start"}
    core = [f for f in feature_matrix() if f.command in core_cmds]
    assert len(core) == len(core_cmds)
    assert all(f.tier == SupportTier.CORE for f in core)


def test_distribution_summary_mentions_pip() -> None:
    summary = distribution_summary()
    assert "pip" in summary["package"]
    assert summary["entrypoint"]
