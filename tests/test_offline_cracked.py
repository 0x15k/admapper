from __future__ import annotations

import json
from pathlib import Path
from admapper.graph.dashboard_server import DashboardContext
from admapper.graph.ops_progress import OpsProgress

def test_sync_offline_cracked_hashes(tmp_path: Path) -> None:
    ws_path = tmp_path / "workspace"
    ws_path.mkdir()
    
    # 1. Setup credentials.json
    creds_path = ws_path / "credentials.json"
    creds_path.write_text(json.dumps({
        "credentials": [
            {
                "id": "c1",
                "username": "svc_user",
                "secret": "original_hash",
                "type": "ntlm",
                "domain": "target.example",
                "status": "unverified",
                "source": "spray"
            }
        ]
    }))
    
    # 2. Setup loot directory and cracked file
    loot_dir = ws_path / "loot"
    loot_dir.mkdir()
    
    cracked_file = loot_dir / "cracked.txt"
    cracked_file.write_text("svc_user:CrackedPassword123!\n")
    
    # 3. Setup context
    ctx = DashboardContext(
        ws_path=ws_path,
        workspace="workspace",
        domain="target.example",
        owned_users=[],
        pivot_user=None,
        host="192.168.10.130"
    )
    
    # Run sync method
    ctx._sync_offline_cracked_hashes()
    
    # 4. Verify credentials.json got updated
    data = json.loads(creds_path.read_text(encoding="utf-8"))
    creds = data["credentials"]
    assert len(creds) == 1
    assert creds[0]["username"] == "svc_user"
    assert creds[0]["secret"] == "CrackedPassword123!"
    assert creds[0]["status"] == "valid"
    assert creds[0]["type"] == "password"
    
    # 5. Verify progress got updated
    assert "svc_user" in ctx.progress.owned_users
    assert "svc_user" in ctx.progress.verified_users
    assert ctx.progress.owned_methods.get("svc_user") == "password"
