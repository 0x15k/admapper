"""macOS-friendly WinRM (pypsrp + Kerberos) — cross-platform fallback for modern AD engagements."""

from admapper.winrm.client import WinRMClient, WinRMError
from admapper.winrm.shell_cli import run_winrm_shell

__all__ = ["WinRMClient", "WinRMError", "run_winrm_shell"]
