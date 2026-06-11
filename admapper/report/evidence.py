from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from admapper import __version__
from admapper.report.collect import CollectedReport
from admapper.report.summary import build_summary


def build_evidence_export(
    collected: CollectedReport,
    *,
    workspace: str,
    domain: str | None,
) -> dict[str, Any]:
    """Phase 17.1 — normalized JSON evidence bundle."""
    return {
        "schema_version": "1.0",
        "generator": "ADMapper",
        "generator_version": __version__,
        "workspace": workspace,
        "domain": domain,
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": build_summary(collected.items),
        "findings": [item.to_dict() for item in collected.items],
    }


def write_evidence_export(path: Path, payload: dict[str, Any]) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
