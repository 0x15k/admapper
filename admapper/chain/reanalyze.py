from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.support.output import print_info, print_success, print_warning

if TYPE_CHECKING:
    from admapper.support.session import Session


def run_followon_analysis(session: Session, *, new_user: str | None = None) -> None:
    """Re-run analysis modules after gaining a new owned principal."""
    if session.workspace is None:
        return

    label = new_user or "new principal"
    print_info(f"follow-on analysis after owning {label}")

    from admapper.adcs.analyze import run_adcs_analysis
    from admapper.chain.analyze import run_chain_analysis
    from admapper.postex.analyze import run_postex_analysis
    from admapper.wsus.analyze import run_wsus_analysis

    modules = (
        ("postex", run_postex_analysis),
        ("adcs", run_adcs_analysis),
        ("wsus", run_wsus_analysis),
        ("chain", run_chain_analysis),
    )
    for name, runner in modules:
        try:
            if name == "postex":
                runner(session)
            else:
                runner(session)
            print_success(f"follow-on: {name} OK")
        except (ValueError, RuntimeError, ImportError) as exc:
            print_warning(f"follow-on {name}: {exc}")
