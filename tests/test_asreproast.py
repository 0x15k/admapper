from pathlib import Path
from unittest.mock import patch

from admapper.core.config import GlobalConfig
from admapper.core.hosts import HostsStore
from admapper.core.session import Session
from admapper.core.users import UsersStore
from admapper.core.workspace import WorkspaceManager
from admapper.creds.asreproast import _parse_getnpusers_output, run_asreproast
from admapper.models.hash_record import AsRepHash
from admapper.models.host import HostRecord
from admapper.models.user import UserRecord, apply_uac_flags

UAC_DONT_REQ_PREAUTH = 0x400000


def test_parse_getnpusers_hashcat_output() -> None:
    stdout = (
        "Impacket v0.12.0\n"
        "$krb5asrep$23$svc@TARGET.EXAMPLE:deadbeef\n"
        "$krb5asrep$23$admin@TARGET.EXAMPLE:beefdead\n"
    )
    hashes = _parse_getnpusers_output(stdout, "target.example")
    assert len(hashes) == 2
    assert hashes[0].username == "svc"
    assert hashes[0].hashcat.startswith("$krb5asrep$")


def test_run_asreproast_stores_hashes(tmp_path: Path) -> None:
    manager = WorkspaceManager(tmp_path / "ws")
    session = Session(config=GlobalConfig(), workspaces=manager)
    session.select_workspace("lab")
    session.set_domain("target.example")
    HostsStore(manager, "lab").merge(
        [HostRecord(address="10.0.0.1", open_ports=[88, 389], is_domain_controller=True)]
    )
    users_store = UsersStore(manager, "lab")
    users_store.merge(
        [
            apply_uac_flags(
                UserRecord(username="svc", sources=["ldap"], uac=UAC_DONT_REQ_PREAUTH)
            )
        ]
    )

    fake_hashes = [AsRepHash(username="svc", domain="target.example", hashcat="$krb5asrep$23$svc@corp")]

    with (
        patch("admapper.creds.asreproast.confirm", return_value=True),
        patch("admapper.creds.asreproast.request_asrep_hashes", return_value=(fake_hashes, None)),
        patch("admapper.creds.asreproast.crack_with_hashcat", return_value={}),
        patch("admapper.creds.asreproast.crack_with_john", return_value={}),
        patch("admapper.creds.asreproast.print_manual_guide"),
    ):
        result = run_asreproast(session, crack=False)

    assert len(result.hashes) == 1
    assert (tmp_path / "ws" / "lab" / "asreproast_hashes.json").is_file()
    assert (tmp_path / "ws" / "lab" / "asreproast_hashcat.txt").is_file()
