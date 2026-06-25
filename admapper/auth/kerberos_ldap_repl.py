"""Long-lived LDAP REPL under Kerberos (for Protected Users). Reads JSON lines from stdin."""

from __future__ import annotations

import base64
import json
import sys
from typing import Any


def _attr_values(raw: dict[str, list[bytes]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for key, values in raw.items():
        decoded: list[str] = []
        for value in values:
            if isinstance(value, bytes):
                if key.lower() in ("objectsid", "ntsecuritydescriptor"):
                    decoded.append(value.decode("latin-1"))
                else:
                    decoded.append(value.decode("utf-8", errors="replace"))
            else:
                decoded.append(str(value))
        out[key] = decoded
    return out


def _parse_entry(search_result: Any) -> dict[str, Any] | None:
    try:
        if hasattr(search_result, "getComponentByName"):
            object_name = search_result.getComponentByName("objectName")
            dn = str(object_name) if object_name is not None else ""
            attrs_component = search_result.getComponentByName("attributes")
            raw_attrs: dict[str, list[bytes]] = {}
            if attrs_component is not None:
                for idx in range(len(attrs_component)):
                    part = attrs_component.getComponentByPosition(idx)
                    name = str(part.getComponentByName("type"))
                    vals_component = part.getComponentByName("vals")
                    values: list[bytes] = []
                    if vals_component is not None:
                        for vidx in range(len(vals_component)):
                            values.append(bytes(vals_component.getComponentByPosition(vidx)))
                    raw_attrs[name] = values
            return {"dn": dn, "attributes": _attr_values(raw_attrs)}

        dn = str(search_result["objectName"])
        raw_attrs = {}
        for part in search_result.get("attributes", []):
            name = str(part["type"])
            vals = [bytes(v) for v in part["vals"]]
            raw_attrs[name] = vals
        return {"dn": dn, "attributes": _attr_values(raw_attrs)}
    except (KeyError, TypeError, AttributeError):
        return None


class _ReplState:
    conn: Any = None
    base_dn: str | None = None


def _bind(payload: dict[str, Any], state: _ReplState) -> dict[str, Any]:
    from impacket.ldap import ldap as ldap_impacket

    host = str(payload["host"])
    user = str(payload["user"])
    password = str(payload["password"])
    domain = str(payload["domain"])
    dc_ip = str(payload.get("dc_ip") or host)
    # Kerberos TGS needs ldap/<fqdn>, not ldap/<ip> (KDC_ERR_S_PRINCIPAL_UNKNOWN).
    ldap_host = str(payload.get("ldap_host") or payload.get("dc_fqdn") or host)

    conn = ldap_impacket.LDAPConnection(f"ldap://{ldap_host}", dstIp=dc_ip)
    conn.kerberosLogin(user, password, domain, kdcHost=dc_ip)
    state.conn = conn
    state.base_dn = conn._baseDN or _domain_to_base_dn(domain)
    return {"ok": True, "base_dn": state.base_dn}


def _domain_to_base_dn(domain: str) -> str:
    parts = domain.strip().lower().split(".")
    return ",".join(f"DC={part}" for part in parts if part)


def _search(payload: dict[str, Any], state: _ReplState) -> dict[str, Any]:
    if state.conn is None:
        return {"ok": False, "error": "not bound"}
    base = payload.get("base_dn") or state.base_dn
    filt = str(payload.get("filter") or "(objectClass=*)")
    attrs = list(payload.get("attributes") or [])
    results = state.conn.search(
        searchBase=base,
        searchFilter=filt,
        attributes=attrs,
    )
    entries = []
    for item in results:
        parsed = _parse_entry(item)
        if parsed:
            entries.append(parsed)
    return {"ok": True, "entries": entries}


def _fetch_sd(payload: dict[str, Any], state: _ReplState) -> dict[str, Any]:
    if state.conn is None:
        return {"ok": False, "error": "not bound"}
    from ldap3.protocol.microsoft import security_descriptor_control

    dn = str(payload["dn"])
    controls = security_descriptor_control(sdflags=0x04)
    results = state.conn.search(
        searchBase=dn,
        searchFilter="(objectClass=*)",
        attributes=["nTSecurityDescriptor"],
        searchControls=controls,
    )
    for item in results:
        parsed = _parse_entry(item)
        if not parsed:
            continue
        raw = parsed["attributes"].get("nTSecurityDescriptor", [])
        if not raw:
            continue
        value = raw[0]
        if isinstance(value, str):
            data = value.encode("latin-1", errors="replace")
        else:
            data = bytes(value)
        return {"ok": True, "sd_b64": base64.b64encode(data).decode("ascii")}
    return {"ok": False, "error": "no security descriptor"}


def main() -> int:
    state = _ReplState()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            _reply({"ok": False, "error": f"invalid json: {exc}"})
            continue
        cmd = str(msg.get("cmd", "")).lower()
        try:
            if cmd == "bind":
                result = _bind(msg, state)
            elif cmd == "search":
                result = _search(msg, state)
            elif cmd == "fetch_sd":
                result = _fetch_sd(msg, state)
            elif cmd == "ping":
                result = {"ok": True, "bound": state.conn is not None}
            elif cmd == "quit":
                _reply({"ok": True})
                break
            else:
                result = {"ok": False, "error": f"unknown cmd: {cmd}"}
        except Exception as exc:
            result = {"ok": False, "error": str(exc)}
        _reply(result)
    if state.conn is not None:
        try:
            state.conn.close()
        except Exception:
            pass
    return 0


def _reply(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
