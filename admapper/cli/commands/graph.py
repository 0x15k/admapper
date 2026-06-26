from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.cli.commands._helpers import require_workspace
from admapper.support.output import print_error, print_info, print_success

if TYPE_CHECKING:
    from admapper.support.session import Session


def handle(session: Session, cmd: str, args: list[str]) -> bool | None:
    if cmd == "graph":
        if not require_workspace(session):
            return True
        ws_path = session.workspaces.path_for(session.workspace.name)  # type: ignore[union-attr]
        from admapper.creds.kerberos_skew import ensure_workspace_skew
        from admapper.analysis.user_match import refresh_workspace_intel

        ensure_workspace_skew(ws_path)
        refresh_workspace_intel(ws_path)
        if args and args[0].lower() == "show":
            from admapper.graph.web import write_attack_graph_html

            out = write_attack_graph_html(
                ws_path,
                workspace=session.workspace.name,  # type: ignore[union-attr]
                domain=session.workspace.domain,  # type: ignore[union-attr]
                pivot_user=session.workspace.pivot_user,  # type: ignore[union-attr]
                owned_users=list(session.workspace.owned_users or []),  # type: ignore[union-attr]
            )
            print_success(f"attack graph → {out}")
            print_info(f"abrir: {out.resolve().as_uri()}")
            return True
        from admapper.graph.analyze import run_graph_analysis
        from admapper.graph.web import write_attack_graph_html

        try:
            run_graph_analysis(session)
        except (ValueError, RuntimeError) as exc:
            print_error(str(exc))
            return True
        out = write_attack_graph_html(
            ws_path,
            workspace=session.workspace.name,  # type: ignore[union-attr]
            domain=session.workspace.domain,  # type: ignore[union-attr]
            pivot_user=session.workspace.pivot_user,  # type: ignore[union-attr]
            owned_users=list(session.workspace.owned_users or []),  # type: ignore[union-attr]
        )
        print_success(f"attack graph → {out}")
        print_info(f"abrir: {out.resolve().as_uri()}")
        return True

    if cmd == "paths":
        if not require_workspace(session):
            return True
        if args and args[0].lower() == "show":
            if len(args) < 2:
                print_error("usage: paths show <id>")
                return True
            from admapper.graph.analyze import get_path_detail
            from admapper.graph.render import print_path_detail

            detail = get_path_detail(session, args[1])
            if detail is None:
                print_error(f"path not found: {args[1]} — run paths first")
                return True
            print_path_detail(detail)
            return True

        from admapper.graph.analyze import run_graph_analysis

        try:
            run_graph_analysis(session)
        except ValueError as exc:
            print_error(str(exc))
        except RuntimeError as exc:
            print_error(str(exc))
        return True

    return None
