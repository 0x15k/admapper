from __future__ import annotations

from dataclasses import dataclass, field

from admapper.models.user import UserRecord


@dataclass
class RidCycleResult:
    host: str
    users: list[UserRecord] = field(default_factory=list)
    error: str | None = None
    rids_scanned: int = 0


def cycle_rids(
    host: str,
    *,
    start_rid: int = 500,
    end_rid: int = 2000,
    timeout: int = 10,
) -> RidCycleResult:
    """Resolve usernames by RID brute-force via SAMR LookupIdsInDomain (requires Impacket)."""
    result = RidCycleResult(host=host)
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
        domain_name = resp["Buffer"]["Buffer"][0]["Name"]
        resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle=server_handle, Name=domain_name)
        domain_sid = resp["DomainId"]
        resp = samr.hSamrOpenDomain(
            dce,
            serverHandle=server_handle,
            domainId=domain_sid,
            desiredAccess=samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS,
        )
        domain_handle = resp["DomainHandle"]
        batch_size = 50
        rid_range = list(range(start_rid, end_rid + 1))
        for offset in range(0, len(rid_range), batch_size):
            batch = rid_range[offset : offset + batch_size]
            result.rids_scanned += len(batch)
            try:
                looked = samr.hSamrLookupIdsInDomain(
                    dce,
                    domainHandle=domain_handle,
                    count=len(batch),
                    relativeIds=batch,
                )
            except Exception:
                continue
            names = looked["Names"]["Element"]
            for rid, name in zip(batch, names, strict=False):
                username = str(name or "").strip()
                if not username or username.endswith("$"):
                    continue
                result.users.append(
                    UserRecord(
                        username=username,
                        sources=["rid_cycling"],
                        rid=rid,
                    )
                )
    except Exception as exc:
        result.error = str(exc)
    return result
