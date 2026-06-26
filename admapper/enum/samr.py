from __future__ import annotations

from dataclasses import dataclass, field

from admapper.models.user import UserRecord


@dataclass
class SamrEnumResult:
    host: str
    users: list[UserRecord] = field(default_factory=list)
    error: str | None = None


def enumerate_users_samr(host: str, *, timeout: int = 10) -> SamrEnumResult:
    """Enumerate domain users via SAMR over SMB null session (requires Impacket)."""
    result = SamrEnumResult(host=host)
    try:
        from impacket.dcerpc.v5 import samr, transport
        from impacket.smbconnection import SMBConnection
    except ImportError:
        result.error = "impacket not installed — pip install -e '.[recon]'"
        return result

    try:
        smb = SMBConnection(host, host, sess_port=445, timeout=timeout)
        smb.login("", "")
        binding = f"ncacn_np:{host}[\\pipe\\samr]"
        rpctransport = transport.DCERPCTransportFactory(binding)
        rpctransport.set_smb_connection(smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        connect_path = f"\\\\{host}\x00"
        resp = samr.hSamrConnect(dce, connect_path, samr.MAXIMUM_ALLOWED)
        server_handle = resp["ServerHandle"]
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle=server_handle)
        domains = resp["Buffer"]["Buffer"]
        if not domains:
            result.error = "no SAMR domains returned"
            return result
        domain_name = domains[0]["Name"]
        resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle=server_handle, Name=domain_name)
        domain_sid = resp["DomainId"]
        resp = samr.hSamrOpenDomain(
            dce,
            serverHandle=server_handle,
            domainId=domain_sid,
            desiredAccess=samr.DOMAIN_LOOKUP,
        )
        domain_handle = resp["DomainHandle"]
        enumeration_context = 0
        while True:
            resp = samr.hSamrEnumerateUsersInDomain(
                dce,
                domainHandle=domain_handle,
                enumerationContext=enumeration_context,
                userAccountControl=samr.USER_NORMAL_ACCOUNT,
                preferMaximumLength=True,
            )
            for item in resp["Buffer"]["Buffer"]:
                rid = int(item["RelativeId"])
                username = item["Name"].lower()
                if username.endswith("$"):
                    continue
                result.users.append(
                    UserRecord(
                        username=username,
                        sources=["samr"],
                        rid=rid,
                    )
                )
            enumeration_context = resp["EnumerationContext"]
            if enumeration_context == 0:
                break
    except Exception as exc:
        result.error = str(exc)
    return result
