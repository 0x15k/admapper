"""Unified engagement reporting and methodology API.

Consolidates engagement map, methodology progress, unified phases, and export
for CLI, game UI, and analyst workflows.
"""

from admapper.methodology.unified import (
    ENGAGEMENT_FRAMEWORK,
    GAME_PHASES,
    UNIFIED_PHASES,
    GamePhaseDef,
    PhaseDef,
    build_study_map,
    game_phase_status,
    methodology_progress_lines,
    phase_status_from_workspace,
)
from admapper.report.engagement_map import (
    build_engagement_map,
    build_engagement_summary,
    format_engagement_summary_lines,
    loot_clue_rows,
    print_engagement_map,
)
from admapper.report.export import ExportResult, run_export
from admapper.report.methodology import enum_highlights, methodology_lines

__all__ = [
    "ENGAGEMENT_FRAMEWORK",
    "GAME_PHASES",
    "UNIFIED_PHASES",
    "ExportResult",
    "GamePhaseDef",
    "PhaseDef",
    "build_engagement_map",
    "build_engagement_summary",
    "build_study_map",
    "enum_highlights",
    "format_engagement_summary_lines",
    "game_phase_status",
    "loot_clue_rows",
    "methodology_lines",
    "methodology_progress_lines",
    "phase_status_from_workspace",
    "print_engagement_map",
    "run_export",
]
