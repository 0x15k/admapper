from __future__ import annotations

from collections import Counter
from typing import Any

from admapper.models.report_item import ReportItem


def build_summary(items: list[ReportItem]) -> dict[str, Any]:
    by_severity = Counter(item.severity for item in items)
    by_category = Counter(item.category for item in items)
    mitre_ids = sorted(
        {
            item.mitre_id
            for item in items
            if item.mitre_id and str(item.mitre_id).startswith("T")
        }
    )
    return {
        "total_items": len(items),
        "by_severity": dict(by_severity),
        "by_category": dict(by_category),
        "mitre_techniques": mitre_ids,
    }
