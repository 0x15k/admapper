from admapper.adcs.analyze import _build_group_enroll_hints
from admapper.acl.enum import PrincipalContext
from admapper.core.owned import is_valid_owned_username, sanitize_owned_users
from admapper.models.adcs import CertificateTemplateRecord


def test_sanitize_owned_removes_aes_artifact() -> None:
    clean, removed = sanitize_owned_users(
        ["wallace.everette", "msa_health$", "aes128-cts-hmac-sha1-96:$", "jaylee.clifton"]
    )
    assert "aes128-cts-hmac-sha1-96:$" in removed
    assert clean == ["wallace.everette", "msa_health$", "jaylee.clifton"]


def test_is_valid_owned_username() -> None:
    assert is_valid_owned_username("jaylee.clifton")
    assert is_valid_owned_username("msa_health$")
    assert not is_valid_owned_username("aes128-cts-hmac-sha1-96:$")


def test_group_enroll_hints_only_confirmed_aces() -> None:
    it_sid = "S-1-5-21-1-2-3-1105"
    templates = [
        CertificateTemplateRecord(
            name="UpdateSrv",
            low_priv_enrollment=False,
            security_aces=[{"trustee_sid": it_sid, "rights": ["enroll"]}],
        ),
        CertificateTemplateRecord(
            name="DomainController",
            low_priv_enrollment=False,
            security_aces=[{"trustee_sid": "S-1-5-21-1-2-3-512", "rights": ["enroll"]}],
        ),
    ]
    principals = [
        PrincipalContext(
            username="jaylee.clifton",
            user_dn="CN=jaylee,DC=logging,DC=htb",
            user_sid="S-1-5-21-1-2-3-2100",
            group_sids={it_sid: "IT"},
            sid_to_name={it_sid: "IT"},
        )
    ]
    hints = _build_group_enroll_hints(principals, templates)
    assert hints.get("jaylee.clifton") == ["UpdateSrv"]
