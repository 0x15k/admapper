from __future__ import annotations

import sys
from dataclasses import dataclass


@dataclass
class WinRMDeps:
    pypsrp: bool
    gssapi: bool
    krb5: bool
    impacket: bool
    mit_kinit: str | None


def check_winrm_deps() -> WinRMDeps:
    from admapper.core.platform import resolve_mit_krb5_bin

    mit_kinit = resolve_mit_krb5_bin("kinit")

    def _try(name: str) -> bool:
        try:
            __import__(name)
            return True
        except ImportError:
            return False

    return WinRMDeps(
        pypsrp=_try("pypsrp"),
        gssapi=_try("gssapi"),
        krb5=_try("krb5"),
        impacket=_try("impacket"),
        mit_kinit=mit_kinit,
    )


def winrm_deps_hint(deps: WinRMDeps | None = None) -> str:
    deps = deps or check_winrm_deps()
    missing = []
    if not deps.pypsrp:
        missing.append("pypsrp")
    if not deps.gssapi:
        missing.append("gssapi")
    if not deps.krb5:
        missing.append("krb5")
    pip = f"{sys.executable} -m pip install"
    lines = [f"{pip} pypsrp gssapi krb5"]
    if not deps.mit_kinit:
        from admapper.core.platform import mit_krb5_install_hint

        lines.append(f"{mit_krb5_install_hint()}  # MIT kinit/kvno for Kerberos WinRM")
    else:
        lines.append(f"MIT kinit: {deps.mit_kinit}")
    if missing:
        lines.insert(0, f"Missing Python packages: {', '.join(missing)}")
    return "\n".join(lines)
