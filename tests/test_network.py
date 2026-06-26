from admapper.core.network import _parse_darwin_ifconfig, resolve_callback_ip


def test_detect_vpn_utun6() -> None:
    sample = """
utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
\tinet 100.64.0.50 --> 100.64.0.50 netmask 0xfffffe00
\tinet6 fe80::aca2:f37a:fc29:6651%utun6 prefixlen 64 scopeid 0x19
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 198.51.100.40 netmask 0xffffff00 broadcast 198.51.100.255
"""
    candidates = _parse_darwin_ifconfig(sample)
    ips = {c.address for c in candidates}
    assert "100.64.0.50" in ips
    assert "198.51.100.40" not in ips
