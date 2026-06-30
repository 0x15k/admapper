#!/usr/bin/env python3
"""Import AD_COMMANDS from cheatsheet commands.js → cheatsheet_catalog.json."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "New AD cheetsheet" / "js" / "data" / "commands.js"
OUT = ROOT / "admapper" / "guides" / "cheatsheet_catalog.json"

_EXTRACT_JS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const marker = 'const AD_COMMANDS = ';
const start = src.indexOf(marker);
if (start < 0) { console.error('AD_COMMANDS not found'); process.exit(1); }
let i = src.indexOf('{', start);
let depth = 0;
let end = i;
for (; end < src.length; end++) {
  const c = src[end];
  if (c === '{') depth++;
  else if (c === '}') { depth--; if (depth === 0) break; }
}
const obj = eval('(' + src.slice(i, end + 1) + ')');
process.stdout.write(JSON.stringify(obj));
"""


def main() -> int:
    if not SRC.is_file():
        print(f"missing source: {SRC}", file=sys.stderr)
        return 1
    proc = subprocess.run(
        ["node", "-e", _EXTRACT_JS, str(SRC)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print(proc.stderr or proc.stdout, file=sys.stderr)
        return proc.returncode
    raw = json.loads(proc.stdout)
    phases: list[dict] = []
    for phase_key, phase in raw.items():
        if not isinstance(phase, dict):
            continue
        subsections: list[dict] = []
        for sub_key, sub in (phase.get("subsections") or {}).items():
            if not isinstance(sub, dict):
                continue
            commands = []
            for cmd in sub.get("commands") or []:
                if not isinstance(cmd, dict):
                    continue
                commands.append(
                    {
                        "id": cmd.get("id"),
                        "title": cmd.get("title"),
                        "tool": cmd.get("tool"),
                        "tags": list(cmd.get("tags") or []),
                        "opsec": cmd.get("opsec"),
                        "description": cmd.get("description"),
                        "command": cmd.get("command"),
                        "next_steps": list(cmd.get("nextSteps") or cmd.get("next_steps") or []),
                        "admapper_action": _infer_action(cmd),
                    }
                )
            subsections.append(
                {
                    "key": sub_key,
                    "label": sub.get("label") or sub_key,
                    "commands": commands,
                }
            )
        phases.append(
            {
                "key": phase_key,
                "label": phase.get("label") or phase_key,
                "icon": phase.get("icon") or "",
                "color": phase.get("color") or "",
                "subsections": subsections,
            }
        )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"phases": phases}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(phases)} phases → {OUT}")
    return 0


def _infer_action(cmd: dict) -> dict | None:
    text = str(cmd.get("command") or "")
    title = str(cmd.get("title") or "").lower()
    tool = str(cmd.get("tool") or "").lower()
    low = text.lower().strip()
    if low.startswith("admapper "):
        return {"type": "cli", "template": text.strip(), "vars_required": ["workspace"]}
    if "postex run" in low or "postex wsus" in low:
        return {"type": "cli", "template": text.strip(), "vars_required": ["workspace"]}
    if "asreproast" in title or ("--asreproast" in low and "ldap" in low):
        return {"type": "phase", "endpoint": "/api/asreproast", "body": {}}
    if "kerberoast" in title and ("ldap" in low or "kerberoasting" in low):
        return {"type": "phase", "endpoint": "/api/kerberoast", "body": {}}
    if "bloodhound-python" in low or "bloodhound collect" in title:
        return {"type": "phase", "endpoint": "/api/bloodhound", "body": {"collect": "All"}}
    if "sharphound" in low and "-c all" in low.replace(" ", ""):
        return {"type": "phase", "endpoint": "/api/bloodhound", "body": {"collect": "All"}}
    if "enum users" in title or "user enumeration" in title:
        return {"type": "phase", "endpoint": "/api/enum", "body": {}}
    if "spray" in title and "password" in low:
        return {"type": "phase", "endpoint": "/api/spray", "body": {"password": "{PASSWORD}"}}
    if "acl" in title and "analysis" in title:
        return {"type": "phase", "endpoint": "/api/acls", "body": {}}
    if "exploit" in title and tool.startswith("admapper"):
        return {"type": "phase", "endpoint": "/api/exploit", "body": {}}
    if "secretsdump" in low or "impacket" in low:
        return None
    if "nxc " in low or "netexec" in low or "crackmapexec" in low:
        return None
    return None


if __name__ == "__main__":
    raise SystemExit(main())
