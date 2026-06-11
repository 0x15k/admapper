"""macOS-friendly WinRM (pypsrp + Kerberos) — alternative to broken evil-winrm/nxc -k."""

from admapper.winrm.client import WinRMClient, WinRMError
from admapper.winrm.shell_cli import run_winrm_shell

__all__ = ["WinRMClient", "WinRMError", "run_winrm_shell"]
