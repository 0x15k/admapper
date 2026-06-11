from admapper.recon.targets import parse_targets


def test_parse_single_ip() -> None:
    assert parse_targets("192.168.1.10") == ["192.168.1.10"]


def test_parse_cidr_caps_at_slash_24() -> None:
    hosts = parse_targets("10.0.0.0/8")
    assert len(hosts) == 254
    assert "10.0.0.1" in hosts


def test_parse_comma_separated() -> None:
    assert parse_targets("10.0.0.1,10.0.0.2") == ["10.0.0.1", "10.0.0.2"]
