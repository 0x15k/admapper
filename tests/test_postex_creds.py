import json
from pathlib import Path
from unittest.mock import MagicMock

from admapper.postex.creds import resolve_winrm_cred


def test_resolve_winrm_cred_uses_gmsa_host_not_dc(tmp_path: Path) -> None:
    ws = tmp_path / "target-192-168-10-182"
    ws.mkdir()
    (ws / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {
                        "account": "msa_target$",
                        "nthash": "a" * 32,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (ws / "unauth_scan.json").write_text(
        json.dumps(
            {
                "hosts": [
                    {
                        "address": "192.168.10.182",
                        "is_domain_controller": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    session = MagicMock()
    session.workspace.name = "target-192-168-10-182"
    session.workspace.domain = "target.example"
    session.workspace.owned_users = ["msa_target$"]
    session.workspaces.path_for.return_value = ws
    session.credentials.list.return_value = []

    cred = resolve_winrm_cred(session)
    assert cred.username == "msa_target$"
    assert cred.host == "dc01.target.example"
    assert cred.nthash == "a" * 32

