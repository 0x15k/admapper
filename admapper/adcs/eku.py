from __future__ import annotations

from typing import Any

from admapper.adcs.constants import CT_FLAG_MACHINE_TYPE

# Extended Key Usage OIDs (Microsoft AD CS)
EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_PKINIT = "1.3.6.1.5.2.3.2"
EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"


def classify_template_eku(eku_list: list[str] | None) -> dict[str, Any]:
    """Classify whether a template cert supports PKINIT/certipy auth or WSUS-only (server auth)."""
    ekus = set(eku_list or [])
    server_auth = EKU_SERVER_AUTH in ekus
    client_auth = EKU_CLIENT_AUTH in ekus
    pkinit = EKU_PKINIT in ekus
    smartcard = EKU_SMARTCARD_LOGON in ekus

    cert_auth_viable = client_auth or pkinit or smartcard
    wsus_chain_step = server_auth and not cert_auth_viable

    labels: list[str] = []
    if server_auth:
        labels.append("Server Authentication")
    if client_auth:
        labels.append("Client Authentication")
    if pkinit:
        labels.append("PKINIT")

    return {
        "server_auth": server_auth,
        "client_auth": client_auth,
        "pkinit": pkinit,
        "cert_auth_viable": cert_auth_viable,
        "wsus_chain_step": wsus_chain_step,
        "eku_labels": labels,
    }


def template_profile_from_inventory(
    inventory: dict[str, Any] | None,
    template_name: str,
) -> dict[str, Any]:
    for item in (inventory or {}).get("templates") or []:
        if str(item.get("name") or "") == template_name:
            flags = int(item.get("enrollment_flags") or 0)
            profile = classify_template_eku(list(item.get("extended_key_usage") or []))
            profile["enrollee_supplies_subject"] = bool(item.get("enrollee_supplies_subject"))
            profile["machine_context"] = bool(flags & CT_FLAG_MACHINE_TYPE)
            profile["enrollment_flags"] = flags
            profile["template"] = template_name
            return profile
    return {}
