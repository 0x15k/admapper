import json
from pathlib import Path
from unittest.mock import MagicMock

from admapper.postex.creds import resolve_winrm_cred


def test_resolve_winrm_cred_uses_gmsa_host_not_dc(tmp_path: Path) -> None:
    ws = tmp_path / "target-10-129-20-182"
    ws.mkdir()
    (ws / "exploit_log.json").write_text(
        json.dumps(
            {
                "new_hashes": [
                    {
                        "account": "msa_health$",
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
                        "address": "10.129.20.182",
                        "is_domain_controller": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    session = MagicMock()
    session.workspace.name = "target-10-129-20-182"
    session.workspace.domain = "logging.htb"
    session.workspace.owned_users = ["msa_health$"]
    session.workspaces.path_for.return_value = ws
    session.credentials.list.return_value = []

    cred = resolve_winrm_cred(session)
    assert cred.username == "msa_health$"
    assert cred.host == "msa_health.logging.htb"
    assert cred.nthash == "a" * 32
