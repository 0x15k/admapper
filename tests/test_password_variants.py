from admapper.creds.password_variants import password_year_variants


def test_password_year_variants_adjacent_years():
    variants = password_year_variants("WelcomePassword123!")
    assert "WelcomePassword123!" in variants
    assert "WelcomePassword123!" in variants
    assert "Em3rg3ncyPa$$2024" in variants


def test_password_year_variants_no_year_suffix():
    assert password_year_variants("SecretPass!") == ["SecretPass!"]
