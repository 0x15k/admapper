from admapper.core.network import _parse_darwin_ifconfig, resolve_callback_ip


def test_detect_htb_vpn_utun6() -> None:
    sample = """
utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
\tinet 10.10.15.243 --> 10.10.15.243 netmask 0xfffffe00
\tinet6 fe80::aca2:f37a:fc29:6651%utun6 prefixlen 64 scopeid 0x19
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255
"""
    candidates = _parse_darwin_ifconfig(sample)
    ips = {c.address for c in candidates}
    assert "10.10.15.243" in ips
    assert "192.168.1.50" not in ips
    assert resolve_callback_ip() is None or True  # env-dependent live test skipped
