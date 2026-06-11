from __future__ import annotations

from typing import Any

from admapper.core.output import print_info, print_table, print_warning


def print_path_detail(path: dict[str, Any]) -> None:
    """Phase 9.5 — step-by-step path narrative."""
    print_info(
        f"Path {path.get('id')}: {path.get('source_label')} → {path.get('target_label')} "
        f"({path.get('length')} hops, impact={path.get('impact')})"
    )
    steps = path.get("steps") or []
    if not steps:
        print_warning("path has no steps")
        return
    rows = [
        [
            str(idx),
            step.get("edge_type", ""),
            step.get("narrative", ""),
            step.get("mitre_id") or "-",
        ]
        for idx, step in enumerate(steps, start=1)
    ]
    print_table("Steps", ["#", "relation", "narrative", "mitre"], rows)
