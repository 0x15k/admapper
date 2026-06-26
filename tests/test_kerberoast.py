from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.users import UsersStore
from admapper.core.workspace import WorkspaceManager
from admapper.creds.kerberoast import _parse_getuserspns_output, run_kerberoast
from admapper.models.hash_record import TgsHash
from admapper.models.host import HostRecord
from admapper.models.user import UserRecord

TGS_SAMPLE = (
    "$krb5tgs$23$*sqlsvc$TARGET.EXAMPLE$MSSQLSvc/dc01.target.example:1433*$deadbeef"
)


def test_parse_getuserspns_hashcat_output() -> None:
    stdout = f"Impacket v0.12.0\n{TGS_SAMPLE}\n"
    hashes = _parse_getuserspns_output(stdout, "target.example")
    assert len(hashes) == 1
    assert hashes[0].username == "sqlsvc"
    assert hashes[0].spn == "MSSQLSvc/dc01.target.example:1433"


def test_run_kerberoast_stores_hashes(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[88, 389], is_domain_controller=True)]
    )
    UsersStore(manager, "lab").merge(
        [
            UserRecord(
                username="sqlsvc",
                sources=["ldap"],
                spns=["MSSQLSvc/dc01.target.example:1433"],
                kerberoastable=True,
            )
        ]
    )

    fake = [
        TgsHash(
            username="sqlsvc",
            domain="target.example",
            spn="MSSQLSvc/dc01.target.example:1433",
            hashcat=TGS_SAMPLE,
        )
    ]

    with (
        patch("admapper.creds.kerberoast.confirm", return_value=True),
        patch(
            "admapper.creds.kerberoast.request_tgs_hashes",
            return_value=(fake, None, "no-pass"),
        ),
        patch("admapper.creds.kerberoast.crack_with_hashcat", return_value={}),
        patch("admapper.creds.kerberoast.crack_with_john", return_value={}),
        patch("admapper.creds.kerberoast.print_manual_guide"),
    ):
        result = run_kerberoast(session, crack=False)

    assert len(result.hashes) == 1
    assert (tmp_path / "ws" / "lab" / "kerberoast_hashes.json").is_file()
    assert (tmp_path / "ws" / "lab" / "kerberoast_hashcat.txt").is_file()
