"""AD Ops interactive UI — re-exports for backward compatibility."""

from admapper.graph.ops_html import build_ops_html, write_ops_html
from admapper.graph.ops_payload import build_ops_payload

__all__ = ["build_ops_html", "build_ops_payload", "write_ops_html"]
