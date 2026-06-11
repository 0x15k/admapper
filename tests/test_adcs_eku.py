from admapper.adcs.eku import EKU_CLIENT_AUTH, EKU_SERVER_AUTH, classify_template_eku


def test_update_srv_is_wsus_chain_only() -> None:
    profile = classify_template_eku([EKU_SERVER_AUTH])
    assert profile["server_auth"] is True
    assert profile["client_auth"] is False
    assert profile["cert_auth_viable"] is False
    assert profile["wsus_chain_step"] is True


def test_client_auth_allows_certipy_auth() -> None:
    profile = classify_template_eku([EKU_SERVER_AUTH, EKU_CLIENT_AUTH])
    assert profile["cert_auth_viable"] is True
    assert profile["wsus_chain_step"] is False
