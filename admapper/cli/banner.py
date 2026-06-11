from __future__ import annotations

from admapper import __version__
from admapper.core.output import print_banner, print_info

# Tres pasos — menos es más (ADscan / AdStrike Smart Analyst).
WORKFLOW_LINES = (
    "  scan -H <DC_IP>                    # sin creds",
    "  run -H <ip> -u <user> -p '<pass>'  # auth + analyst (default)",
    "  analyst -w <workspace>             # refrescar escenario",
)


def print_workflow_banner(*, title: str | None = None) -> None:
    print_banner(
        title or f"ADMapper v{__version__}",
        "scan → run → analyst",
    )
    for line in WORKFLOW_LINES:
        print_info(line)
