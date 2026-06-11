from admapper.recon.dns import infer_domain_from_hostname


def test_infer_domain_from_hostname() -> None:
    assert infer_domain_from_hostname("dc01.corp.local") == "corp.local"
    assert infer_domain_from_hostname("dc01.corp.local.") == "corp.local"


def test_infer_domain_short_hostname_returns_none() -> None:
    assert infer_domain_from_hostname("dc01") is None
