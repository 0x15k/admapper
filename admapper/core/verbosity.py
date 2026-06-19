from __future__ import annotations

_verbose: bool = False


def set_verbose(value: bool) -> None:
    global _verbose
    _verbose = value


def is_verbose() -> bool:
    return _verbose


def is_compact() -> bool:
    """Game UI / learner mode — short structured output, no raw CLI dumps."""
    from admapper.core.dashboard_mode import is_dashboard_mode

    return is_dashboard_mode()


def print_phase(message: str) -> None:
    """Print phase banners only in verbose mode."""
    if _verbose:
        from admapper.core.output import print_info

        print_info(message)


def quiet_info(message: str) -> None:
    """Sub-step detail — only when verbose."""
    print_phase(message)


def quiet_success(message: str) -> None:
    """Success detail — only when verbose."""
    if _verbose:
        from admapper.core.output import print_success

        print_success(message)


def quiet_warning(message: str) -> None:
    """Warning detail — only when verbose."""
    if _verbose:
        from admapper.core.output import print_warning

        print_warning(message)
