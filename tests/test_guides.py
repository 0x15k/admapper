from admapper.guides.catalog import get_manual_guide


def test_manual_guide_catalog_has_phase2_entries() -> None:
    for key in ("ldap_user_enum", "samr_enumeration", "rid_cycling", "asreproast"):
        guide = get_manual_guide(key)
        assert guide is not None
        assert guide.manual_steps
        assert guide.commands


def test_ldap_anonymous_guide_has_mitre() -> None:
    guide = get_manual_guide("ldap_anonymous")
    assert guide is not None
    assert guide.mitre_id == "T1087.002"
    assert "ldapsearch" in guide.commands[0]
