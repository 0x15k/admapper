from __future__ import annotations

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory

from admapper.cli.banner import print_workflow_banner
from admapper.cli.commands import dispatch
from admapper.support.config import ensure_config_dir
from admapper.support.output import print_info
from admapper.support.paths import global_config_dir
from admapper.support.session import Session


def run_shell(session: Session | None = None) -> None:
    """Start the interactive ADMapper REPL."""
    ensure_config_dir()
    session = session or Session.bootstrap()
    history_path = global_config_dir() / "history"
    prompt = PromptSession(
        history=FileHistory(str(history_path)),
        auto_suggest=AutoSuggestFromHistory(),
    )

    print_workflow_banner()
    print_info("help = esencial | show = dashboard | analyst = escenario completo")

    while True:
        try:
            line = prompt.prompt(f"({session.prompt_label()})> ")
        except (EOFError, KeyboardInterrupt):
            print()
            if session.workspace is not None:
                session.persist_workspace()
            break
        if not dispatch(session, line):
            break
