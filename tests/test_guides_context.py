from admapper.guides.context import GuideContext, contextualize_text, domain_to_base_dn


def test_domain_to_base_dn() -> None:
    assert domain_to_base_dn("target.example") == "DC=target,DC=example"


def test_contextualize_ldap_commands() -> None:
    ctx = GuideContext(
        domain="target.example",
        dc_ip="10.0.0.1",
        dc_host="dc01.target.example",
        base_dn="DC=target,DC=example",
        username="target.user",
        password="KnownPassword123!",
    )
    cmd = 'ldapsearch -x -H ldap://<DC_IP> -b "DC=target,DC=example" sAMAccountName'
    result = contextualize_text(cmd, ctx)
    assert "10.0.0.1" in result
    assert "DC=target,DC=example" in result


def test_contextualize_impacket_creds() -> None:
    ctx = GuideContext(
        domain="target.example",
        dc_ip="10.0.0.1",
        username="target.user",
        password="KnownPassword123!",
    )
    cmd = "GetUserSPNs.py <DOMAIN>/user:pass -dc-ip <DC_IP> -request"
    result = contextualize_text(cmd, ctx)
    assert "target.example/target.user:KnownPassword123!" in result
    assert "10.0.0.1" in result


def test_contextualize_uncontextualized_text_replaces_with_placeholders() -> None:
    ctx = GuideContext()
    cmd = "GetUserSPNs.py <DOMAIN>/user:pass -dc-ip <DC_IP> -request"
    result = contextualize_text(cmd, ctx)
    assert "<domain>/" in result
    assert "<dc_ip>" in result
