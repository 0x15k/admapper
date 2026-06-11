from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from admapper.models.report_item import ReportItem


def _normalize_technique_id(mitre_id: str) -> str | None:
    raw = mitre_id.strip().upper()
    if not raw.startswith("T"):
        return None
    return raw


def build_navigator_layer(
    items: list[ReportItem],
    *,
    workspace: str,
    domain: str | None,
) -> dict[str, Any]:
    """Phase 17.2 — MITRE ATT&CK Navigator layer JSON."""
    scores: dict[str, int] = defaultdict(int)
    comments: dict[str, list[str]] = defaultdict(list)

    for item in items:
        if not item.mitre_id:
            continue
        technique_id = _normalize_technique_id(str(item.mitre_id))
        if not technique_id:
            continue
        scores[technique_id] += 1
        label = item.title
        if item.host:
            label = f"{label} ({item.host})"
        if label not in comments[technique_id]:
            comments[technique_id].append(label)

    techniques = [
        {
            "techniqueID": technique_id,
            "score": score,
            "comment": "; ".join(comments[technique_id][:5]),
            "enabled": True,
            "metadata": [],
        }
        for technique_id, score in sorted(scores.items())
    ]

    domain_label = domain or workspace
    return {
        "name": f"ADMapper — {domain_label}",
        "versions": {
            "attack": "16",
            "navigator": "5.0.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"ADMapper engagement layer for {domain_label}",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": max(scores.values()) if scores else 1,
        },
        "legendItems": [
            {"label": "not observed", "color": "#ffffff"},
            {"label": "observed", "color": "#ff6666"},
        ],
    }


def write_navigator_layer(path: Path, payload: dict[str, Any]) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
