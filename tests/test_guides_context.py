from admapper.guides.context import GuideContext, contextualize_text, domain_to_base_dn


def test_domain_to_base_dn() -> None:
    assert domain_to_base_dn("corp.local") == "DC=corp,DC=local"


def test_contextualize_ldap_commands() -> None:
    ctx = GuideContext(
        domain="corp.local",
        dc_ip="10.0.0.1",
        dc_host="dc01.corp.local",
        base_dn="DC=corp,DC=local",
        username="wallace.doe",
        password="WelcomePassword123!",
    )
    cmd = 'ldapsearch -x -H ldap://<DC_IP> -b "DC=corp,DC=local" sAMAccountName'
    result = contextualize_text(cmd, ctx)
    assert "10.0.0.1" in result
    assert "DC=corp,DC=local" in result


def test_contextualize_impacket_creds() -> None:
    ctx = GuideContext(
        domain="corp.local",
        dc_ip="10.0.0.1",
        username="wallace.doe",
        password="WelcomePassword123!",
    )
    cmd = "GetUserSPNs.py corp.local/user:pass -dc-ip <DC_IP> -request"
    result = contextualize_text(cmd, ctx)
    assert "corp.local/wallace.doe:WelcomePassword123!" in result
    assert "10.0.0.1" in result


def test_contextualize_uncontextualized_text_replaces_with_placeholders() -> None:
    ctx = GuideContext()
    cmd = "GetUserSPNs.py corp.local/user:pass -dc-ip <DC_IP> -request"
    result = contextualize_text(cmd, ctx)
    assert "<domain>/<username>:<password>" in result
    assert "<dc_ip>" in result
