from __future__ import annotations

from pathlib import Path

from admapper.creds.common import collect_gained_hashes


def pick_best_pivot(owned: list[str], *, ws_path: Path | None = None) -> str | None:
    """Best pivot: lateral human after machine hash, else gMSA, else last human."""
    if not owned:
        return None
    last_machine_idx = max(
        (i for i, user in enumerate(owned) if user.endswith("$")),
        default=-1,
    )
    post_machine_humans = [
        user for i, user in enumerate(owned) if i > last_machine_idx and not user.endswith("$")
    ]
    if post_machine_humans:
        return post_machine_humans[-1]
    if ws_path is not None:
        hashes = collect_gained_hashes(ws_path)
        if hashes:
            return hashes[-1][0]
    for username in reversed(owned):
        if not username.endswith("$"):
            return username
    return None
