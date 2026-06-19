"""AD Ops interactive UI — re-exports for backward compatibility."""

from admapper.graph.game_html import build_game_html, write_game_html
from admapper.graph.game_payload import build_game_payload

__all__ = ["build_game_html", "build_game_payload", "write_game_html"]
