"""Canonical AD engagement phases (P01–P12).

Single source of truth lives in ``admapper.methodology.unified`` — import
``CANONICAL_PHASES`` or ``phase_banner()`` here instead of hard-coding
legacy "Phase N" strings in module banners.
"""

from __future__ import annotations

from admapper.methodology.unified import UNIFIED_PHASES, PhaseDef

CANONICAL_PHASES: tuple[PhaseDef, ...] = UNIFIED_PHASES

_BY_ID: dict[str, PhaseDef] = {p.id: p for p in UNIFIED_PHASES}


def phase_banner(phase_id: str, *, detail: str = "") -> str:
    """Human-readable banner: ``P02 Unauth discovery — …``."""
    ph = _BY_ID.get(phase_id.lower())
    if ph is None:
        return detail or phase_id
    code = f"P{ph.order:02d} {ph.name}"
    return f"{code} — {detail}" if detail else code


def phase_docstring(phase_id: str, summary: str) -> str:
    """Module docstring line referencing the unified model."""
    ph = _BY_ID.get(phase_id.lower())
    if ph is None:
        return summary
    return f"{summary} (canonical: P{ph.order:02d} {ph.name} — see methodology.unified)"
