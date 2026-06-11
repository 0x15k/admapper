from admapper.guides.context import GuideContext, contextualize_text, domain_to_base_dn


def test_domain_to_base_dn() -> None:
    assert domain_to_base_dn("logging.htb") == "DC=logging,DC=htb"


def test_contextualize_ldap_commands() -> None:
    ctx = GuideContext(
        domain="logging.htb",
        dc_ip="10.129.245.130",
        dc_host="DC01.logging.htb",
        base_dn="DC=logging,DC=htb",
        username="wallace.everette",
        password="Welcome2026@",
    )
    cmd = 'ldapsearch -x -H ldap://<DC_IP> -b "DC=corp,DC=local" sAMAccountName'
    result = contextualize_text(cmd, ctx)
    assert "10.129.245.130" in result
    assert "DC=logging,DC=htb" in result
    assert "corp.local" not in result


def test_contextualize_impacket_creds() -> None:
    ctx = GuideContext(
        domain="logging.htb",
        dc_ip="10.129.245.130",
        username="wallace.everette",
        password="Welcome2026@",
    )
    cmd = "GetUserSPNs.py corp.local/user:pass -dc-ip <DC_IP> -request"
    result = contextualize_text(cmd, ctx)
    assert "logging.htb/wallace.everette:Welcome2026@" in result
    assert "10.129.245.130" in result
