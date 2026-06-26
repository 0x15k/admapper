from admapper.creds.password_variants import password_year_variants


def test_password_year_variants_adjacent_years():
    variants = password_year_variants("Password2026")
    assert "Password2026" in variants
    assert "Password2025" in variants
    assert "Password2027" in variants


def test_password_year_variants_no_year_suffix():
    assert password_year_variants("SecretPass") == ["SecretPass"]
