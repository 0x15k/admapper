#!/usr/bin/env python3
"""Import EDGE_ABUSE from cheatsheet attackGraph.js → edge_abuse_catalog.json."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "New AD cheetsheet" / "js" / "modules" / "attackGraph.js"
OUT = ROOT / "admapper" / "graph" / "edge_abuse_catalog.json"

_EXTRACT_JS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const marker = 'const EDGE_ABUSE = ';
const start = src.indexOf(marker);
if (start < 0) { console.error('EDGE_ABUSE not found'); process.exit(1); }
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
    sys.path.insert(0, str(ROOT))
    from admapper.graph.edge_abuse import entry_to_catalog_dict, normalize_edge_key

    catalog: dict[str, dict] = {}
    unmapped: list[str] = []
    for js_key, js_entry in raw.items():
        if not isinstance(js_entry, dict):
            continue
        item = entry_to_catalog_dict(str(js_key), js_entry)
        edge_key = item["edge_key"]
        if edge_key not in catalog:
            catalog[edge_key] = item
        else:
            catalog[edge_key] = item
        if normalize_edge_key(js_key) == _pascal_to_snake_fallback(js_key) and js_key not in (
            "MemberOf",
            "AdminTo",
        ):
            pass
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(catalog)} entries → {OUT}")
    return 0


def _pascal_to_snake_fallback(name: str) -> str:
    import re

    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()


if __name__ == "__main__":
    raise SystemExit(main())
