from __future__ import annotations

"""Shared workspace JSON loading.

Workspace artifacts are operator-editable plaintext that can be truncated or
hand-corrupted between runs. Reading them must degrade gracefully (return
``None``) instead of crashing a command with ``JSONDecodeError``/``OSError``.
"""

import json
from pathlib import Path
from typing import Any


def load_json(path: str | Path) -> dict[str, Any] | None:
    """Load a JSON object from ``path``.

    Returns ``None`` when the file is missing, unreadable, or not valid JSON.
    """
    path = Path(path)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
