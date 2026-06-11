from __future__ import annotations

from typing import Any


def apply_postex_templates(text: str, ctx: dict[str, Any]) -> str:
    """Replace `<key>` placeholders in catalog strings and commands."""
    out = text
    for key, value in ctx.items():
        if value is None:
            continue
        out = out.replace(f"<{key}>", str(value))
    return out


def build_template_context(
    *,
    domain: str,
    host: str,
    user: str,
    nthash: str | None = None,
    drop_path: str = "",
    payload_zip: str = "",
    payload_dll: str = "",
    task_name: str = "",
    run_as: str = "",
    workspace: str = "",
    op_id: str = "",
) -> dict[str, str]:
    return {
        "domain": domain,
        "host": host,
        "user": user,
        "NTLM": nthash or "<NTLM>",
        "hash": nthash or "<hash>",
        "drop": drop_path,
        "zip": payload_zip,
        "dll": payload_dll,
        "task": task_name,
        "runas": run_as,
        "workspace": workspace,
        "id": op_id or "<id>",
    }
