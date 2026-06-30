"""BloodHound edge abuse catalog — translated from cheatsheet EDGE_ABUSE."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from admapper.graph.catalog import EDGE_CATALOG

_CATALOG_PATH = Path(__file__).with_name("edge_abuse_catalog.json")

# PascalCase / BH names → admapper graph catalog keys
_EDGE_KEY_ALIASES: dict[str, str] = {
    "member_of": "member_of",
    "memberof": "member_of",
    "admin_to": "adminto",
    "adminto": "adminto",
    "has_session": "has_session",
    "hassession": "has_session",
    "can_rdp": "can_rdp",
    "canrdp": "can_rdp",
    "can_ps_remote": "can_psremote",
    "canpsremote": "can_psremote",
    "execute_dcom": "execute_dcom",
    "executedcom": "execute_dcom",
    "force_change_password": "forcechangepassword",
    "forcechangepassword": "forcechangepassword",
    "generic_all": "genericall",
    "genericall": "genericall",
    "generic_write": "genericwrite",
    "genericwrite": "genericwrite",
    "write_dacl": "writedacl",
    "writedacl": "writedacl",
    "write_owner": "writeowner",
    "writeowner": "writeowner",
    "owns": "owns",
    "add_member": "addmember",
    "addmember": "addmember",
    "add_self": "addself",
    "addself": "addself",
    "all_extended_rights": "allextendedrights",
    "allextendedrights": "allextendedrights",
    "read_laps_password": "readlapspassword",
    "readlapspassword": "readlapspassword",
    "read_gmsa_password": "readgmsapassword",
    "readgmsapassword": "readgmsapassword",
    "add_key_credential_link": "shadow_credentials",
    "addkeycredentiallink": "shadow_credentials",
    "shadow_credentials": "shadow_credentials",
    "add_allowed_to_act": "rbcd",
    "addallowedtoact": "rbcd",
    "allowed_to_delegate": "constrained_delegation",
    "allowedtodelegate": "constrained_delegation",
    "dc_sync": "dcsync",
    "dcsync": "dcsync",
    "get_changes": "getchanges",
    "getchanges": "getchanges",
    "get_changes_all": "getchangesall",
    "getchangesall": "getchangesall",
    "sql_admin": "sqladmin",
    "sqladmin": "sqladmin",
    "has_sid_history": "has_sid_history",
    "hassidhistory": "has_sid_history",
    "trusted_by": "trusted_by",
    "trustedby": "trusted_by",
}


@dataclass(frozen=True)
class EdgeAbuseVariant:
    title: str
    command_template: str


@dataclass(frozen=True)
class EdgeAbuseEntry:
    edge_key: str
    title: str
    tool: str
    narrative: str
    default_command: str
    by_target: dict[str, EdgeAbuseVariant] = field(default_factory=dict)
    mitre_id: str = ""
    severity: str = "info"

    @property
    def target_aware(self) -> bool:
        return bool(self.by_target)


@dataclass(frozen=True)
class HopContext:
    from_label: str = ""
    to_label: str = ""
    to_short: str = ""
    to_dn: str = ""


@dataclass(frozen=True)
class ResolvedAbuseStep:
    edge_key: str
    title: str
    tool: str
    narrative: str
    command: str
    raw_command: str
    mitre_id: str = ""
    severity: str = "info"
    target_type: str = ""


def _pascal_to_snake(name: str) -> str:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name.strip())
    return s.lower().replace(" ", "_").replace("-", "_")


def normalize_edge_key(name: str) -> str:
    """BloodHound / path step name → catalog edge_key."""
    if not name:
        return ""
    raw = _pascal_to_snake(name)
    compact = raw.replace("_", "")
    return _EDGE_KEY_ALIASES.get(raw, _EDGE_KEY_ALIASES.get(compact, raw))


def _base_dn(domain: str) -> str:
    if not domain:
        return ""
    return ",".join(f"DC={part}" for part in domain.split(".") if part)


def substitute_command(
    template: str,
    workspace_vars: dict[str, str] | None = None,
    hop: HopContext | None = None,
) -> str:
    """Replace angle/brace/hop tokens; unknown tokens stay literal."""
    ws = {k: str(v or "") for k, v in (workspace_vars or {}).items()}
    domain = ws.get("DOMAIN") or ws.get("domain") or ""
    result = template
    if hop:
        hop_map = {
            "{from}": hop.from_label,
            "{to}": hop.to_label,
            "{toShort}": hop.to_short or hop.to_label,
            "{toDN}": hop.to_dn,
        }
        for tok, val in hop_map.items():
            if val:
                result = result.replace(tok, val)
    angle = {
        "<DOMAIN>": domain,
        "<DC>": ws.get("DC_IP") or ws.get("dc_ip") or "",
        "<DC_IP>": ws.get("DC_IP") or ws.get("dc_ip") or "",
        "<BASE_DN>": ws.get("BASE_DN") or _base_dn(domain),
        "<USER>": ws.get("USERNAME") or ws.get("user") or "",
        "<PASS>": ws.get("PASSWORD") or ws.get("pass") or "",
        "<PASSWORD>": ws.get("PASSWORD") or ws.get("pass") or "",
        "<HASH>": ws.get("NTLM_HASH") or ws.get("hash") or "",
        "<NTLM>": ws.get("NTLM_HASH") or ws.get("hash") or "",
        "<workspace>": ws.get("workspace") or "",
    }
    for tok, val in angle.items():
        if val:
            result = result.replace(tok, val)
    brace = {
        "{DOMAIN}": domain,
        "{DC_IP}": ws.get("DC_IP") or ws.get("dc_ip") or "",
        "{USERNAME}": ws.get("USERNAME") or ws.get("user") or "",
        "{PASSWORD}": ws.get("PASSWORD") or ws.get("pass") or "",
        "{NTLM_HASH}": ws.get("NTLM_HASH") or ws.get("hash") or "",
        "{ATTACKER_IP}": ws.get("ATTACKER_IP") or ws.get("attacker_ip") or "",
        "{CA_NAME}": ws.get("CA_NAME") or ws.get("ca_name") or "",
        "{TEMPLATE}": ws.get("TEMPLATE") or ws.get("template") or "",
    }
    for tok, val in brace.items():
        if val:
            result = result.replace(tok, val)
    return result


def _entry_from_dict(edge_key: str, data: dict[str, Any]) -> EdgeAbuseEntry:
    by_target: dict[str, EdgeAbuseVariant] = {}
    for tgt, variant in (data.get("by_target") or {}).items():
        if isinstance(variant, dict):
            by_target[str(tgt).lower()] = EdgeAbuseVariant(
                title=str(variant.get("title") or ""),
                command_template=str(variant.get("command") or variant.get("command_template") or ""),
            )
    cat = EDGE_CATALOG.get(edge_key)
    return EdgeAbuseEntry(
        edge_key=edge_key,
        title=str(data.get("title") or (cat.title if cat else edge_key)),
        tool=str(data.get("tool") or ""),
        narrative=str(data.get("narrative") or data.get("desc") or ""),
        default_command=str(data.get("default_command") or data.get("cmd") or ""),
        by_target=by_target,
        mitre_id=str(data.get("mitre_id") or (cat.mitre_id if cat else "") or ""),
        severity=str(data.get("severity") or (cat.severity if cat else "info") or "info"),
    )


def load_edge_abuse_catalog(path: Path | None = None) -> dict[str, EdgeAbuseEntry]:
    p = path or _CATALOG_PATH
    if not p.is_file():
        return {}
    raw = json.loads(p.read_text(encoding="utf-8"))
    out: dict[str, EdgeAbuseEntry] = {}
    for key, item in raw.items():
        if isinstance(item, dict):
            out[str(key)] = _entry_from_dict(str(key), item)
    return out


def resolve_edge_abuse(
    edge_key: str,
    *,
    target_type: str = "",
    hop: HopContext | None = None,
    workspace_vars: dict[str, str] | None = None,
    catalog: dict[str, EdgeAbuseEntry] | None = None,
) -> ResolvedAbuseStep:
    cat = catalog or load_edge_abuse_catalog()
    norm = normalize_edge_key(edge_key)
    entry = cat.get(norm)
    if entry is None:
        fallback = f"# No abuse catalog entry for edge {edge_key}"
        return ResolvedAbuseStep(
            edge_key=norm or edge_key,
            title=edge_key,
            tool="",
            narrative="",
            command=substitute_command(fallback, workspace_vars, hop),
            raw_command=fallback,
            target_type=target_type,
        )
    tgt = str(target_type or "").lower()
    if entry.target_aware and tgt and tgt in entry.by_target:
        variant = entry.by_target[tgt]
        raw = variant.command_template
        title = variant.title or entry.title
    else:
        raw = entry.default_command
        title = entry.title
    narrative = substitute_command(entry.narrative, workspace_vars, hop)
    command = substitute_command(raw, workspace_vars, hop)
    return ResolvedAbuseStep(
        edge_key=entry.edge_key,
        title=title,
        tool=entry.tool,
        narrative=narrative,
        command=command,
        raw_command=raw,
        mitre_id=entry.mitre_id,
        severity=entry.severity,
        target_type=tgt,
    )


def edge_abuse_catalog_json() -> str:
    """Serialize catalog for browser (PathPlaybook + Cheatsheet Attack Graph)."""
    cat = load_edge_abuse_catalog()
    payload: dict[str, Any] = {}
    for key, entry in cat.items():
        payload[key] = {
            "title": entry.title,
            "tool": entry.tool,
            "narrative": entry.narrative,
            "default_command": entry.default_command,
            "by_target": {
                t: {"title": v.title, "command": v.command_template}
                for t, v in entry.by_target.items()
            },
            "mitre_id": entry.mitre_id,
            "severity": entry.severity,
            "target_aware": entry.target_aware,
        }
    return json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")


def entry_to_catalog_dict(
    js_key: str,
    js_entry: dict[str, Any],
) -> dict[str, Any]:
    """Convert raw JS EDGE_ABUSE entry to committed JSON shape."""
    edge_key = normalize_edge_key(js_key)
    by_target: dict[str, dict[str, str]] = {}
    cmds = js_entry.get("cmds") or {}
    if isinstance(cmds, dict):
        for tgt, variant in cmds.items():
            if isinstance(variant, dict):
                by_target[str(tgt).lower()] = {
                    "title": str(variant.get("title") or ""),
                    "command": str(variant.get("cmd") or ""),
                }
            elif isinstance(variant, str):
                by_target[str(tgt).lower()] = {"title": str(tgt), "command": variant}
    cat = EDGE_CATALOG.get(edge_key)
    return {
        "edge_key": edge_key,
        "source_key": js_key,
        "title": str(js_entry.get("title") or ""),
        "tool": str(js_entry.get("tool") or ""),
        "narrative": str(js_entry.get("desc") or ""),
        "default_command": str(js_entry.get("cmd") or ""),
        "by_target": by_target,
        "mitre_id": cat.mitre_id if cat else "",
        "severity": cat.severity if cat else "info",
        "target_aware": bool(by_target),
    }
