from __future__ import annotations

from admapper import __version__
from admapper.support.output import console, print_info
from rich.panel import Panel

ADMAPPER_ASCII = r"""
    _    ____  __  __                                 
   / \  |  _ \|  \/  | __ _ _ __  _ __   ___ _ __ 
  / _ \ | | | | |\/| |/ _` | '_ \| '_ \ / _ \ '__|
 / ___ \| |_| | |  | | (_| | |_) | |_) |  __/ |   
/_/   \_\____/|_|  |_|\__,_| .__/| .__/ \___|_|   
                           |_|   |_|              
"""

# Three steps — less is more (ADscan / AdStrike Smart Analyst).
WORKFLOW_LINES = (
    "  scan -H <DC_IP>                    # no creds",
    "  run -H <ip> -u <user> -p '<pass>'  # auth + analyst (default)",
    "  analyst -w <workspace>             # refresh scenario",
)


def print_workflow_banner(*, title: str | None = None) -> None:
    # Print the large ASCII banner in bold cyan
    console.print(ADMAPPER_ASCII, style="bold cyan")
    
    # Print a clean panel with version and steps info
    version_text = f"ADMapper v{__version__} | scan → run → analyst"
    console.print(Panel(version_text, border_style="cyan", padding=(0, 2), expand=False))
    
    # Print workflow lines
    for line in WORKFLOW_LINES:
        print_info(line)
