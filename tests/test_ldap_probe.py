from unittest.mock import patch

from admapper.recon.ldap_probe import (
    LdapProbeResult,
    discover_domain_from_ldap,
    infer_domain_from_hostname,
)


def test_discover_domain_from_rootdse_without_anonymous_bind() -> None:
    probe = LdapProbeResult(
        host="192.168.10.182",
        port=389,
        reachable=True,
        anonymous_bind=False,
        default_naming_context="DC=logging,DC=htb",
        dns_host_name="DC01.corp.local",
    )
    with (
        patch(
            "admapper.recon.ldap_probe.domain_from_tls_certificate",
            return_value=(None, None),
        ),
        patch("admapper.recon.ldap_probe.probe_ldap", return_value=probe),
    ):
        domain, hostname, best = discover_domain_from_ldap("192.168.10.182")
    assert domain == "corp.local"
    assert hostname == "dc01.corp.local"
    assert best is probe


def test_discover_domain_from_certificate_san() -> None:
    with (
        patch(
            "admapper.recon.ldap_probe.domain_from_tls_certificate",
            return_value=("corp.local", "dc01.corp.local"),
        ),
        patch(
            "admapper.recon.ldap_probe.probe_ldap",
            return_value=LdapProbeResult(host="192.168.10.182", port=389, reachable=False),
        ),
    ):
        domain, hostname, _ = discover_domain_from_ldap("192.168.10.182")
    assert domain == "corp.local"
    assert hostname == "dc01.corp.local"


def test_infer_domain_from_hostname_dc() -> None:
    assert infer_domain_from_hostname("DC01.corp.local") == "corp.local"
