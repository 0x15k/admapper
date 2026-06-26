from __future__ import annotations

from typing import Any

from admapper.support.output import print_info, print_success, print_table, print_warning


def print_chain_detail(chain: dict[str, Any]) -> None:
    cid = chain.get("id")
    title = chain.get("title")
    ready = chain.get("ready", False)
    print_success(f"Attack chain {cid}: {title}")
    rows = [
        ["chain", chain.get("chain_id") or ""],
        ["target", chain.get("target_host") or ""],
        ["context", chain.get("context") or ""],
        ["ready", "yes" if ready else "no"],
    ]
    print_table("Chain", ["field", "value"], rows)
    print_info(chain.get("summary", ""))

    steps = chain.get("steps") or []
    if steps:
        print_table(
            "Steps",
            ["#", "module", "technique", "ready", "detail"],
            [
                [
                    str(s.get("order")),
                    str(s.get("module")),
                    str(s.get("technique")),
                    "yes" if s.get("ready") else "no",
                    str((s.get("detail") or "")[:60]),
                ]
                for s in steps
            ],
        )

    commands = chain.get("manual_commands") or []
    if commands:
        print_table("Next actions", ["command"], [[c] for c in commands])
    else:
        print_warning("chain complete or no pending commands")
