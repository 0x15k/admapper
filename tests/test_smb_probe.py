from unittest.mock import MagicMock, patch

from admapper.recon.smb_probe import probe_smb_null


def test_probe_smb_null_extracts_dns_domain() -> None:
    conn = MagicMock()
    conn.getServerDNSDomainName.return_value = "logging.htb"
    conn.getServerDNSHostName.return_value = "dc01.logging.htb"

    with (
        patch("impacket.smbconnection.SMBConnection", return_value=conn),
        patch("impacket.smbconnection.SessionError", Exception),
    ):
        result = probe_smb_null("10.129.20.182")

    assert result.null_session is True
    assert result.dns_domain == "logging.htb"
    assert result.dns_hostname == "dc01.logging.htb"
