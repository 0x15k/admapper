from unittest.mock import patch

from admapper.recon.ldap_probe import (
    LdapProbeResult,
    discover_domain_from_ldap,
    infer_domain_from_hostname,
)


def test_discover_domain_from_rootdse_without_anonymous_bind() -> None:
    probe = LdapProbeResult(
        host="10.129.20.182",
        port=389,
        reachable=True,
        anonymous_bind=False,
        default_naming_context="DC=logging,DC=htb",
        dns_host_name="DC01.logging.htb",
    )
    with (
        patch(
            "admapper.recon.ldap_probe.domain_from_tls_certificate",
            return_value=(None, None),
        ),
        patch("admapper.recon.ldap_probe.probe_ldap", return_value=probe),
    ):
        domain, hostname, best = discover_domain_from_ldap("10.129.20.182")
    assert domain == "logging.htb"
    assert hostname == "dc01.logging.htb"
    assert best is probe


def test_discover_domain_from_certificate_san() -> None:
    with (
        patch(
            "admapper.recon.ldap_probe.domain_from_tls_certificate",
            return_value=("logging.htb", "dc01.logging.htb"),
        ),
        patch(
            "admapper.recon.ldap_probe.probe_ldap",
            return_value=LdapProbeResult(host="10.129.20.182", port=389, reachable=False),
        ),
    ):
        domain, hostname, _ = discover_domain_from_ldap("10.129.20.182")
    assert domain == "logging.htb"
    assert hostname == "dc01.logging.htb"


def test_infer_domain_from_hostname_dc() -> None:
    assert infer_domain_from_hostname("DC01.logging.htb") == "logging.htb"
