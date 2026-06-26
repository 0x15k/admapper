from admapper.chain.analyze import build_attack_chains


def test_build_dll_hijack_chain_detects_pivot() -> None:
    class FakeSession:
        workspace = type("W", (), {"owned_users": ["target.admin"]})()

    session = FakeSession()
    postex_ops = {
        "opportunities": [
            {
                "id": "postex-010",
                "technique": "dll_hijack_scheduled_task",
                "detail": "Task 'UpdateChecker Agent' runs as target.admin | Binary: ...",
            }
        ]
    }
    adcs_findings = {
        "findings": [
            {
                "id": "adcs-002",
                "esc": "template_enrollment",
                "principal": "target.admin",
                "template": "TargetSrv",
            }
        ]
    }
    wsus_ops = {
        "opportunities": [
            {
                "id": "wsus-001",
                "technique": "wsus_cert_chain",
                "context": "target.admin",
                "prerequisites_met": True,
            }
        ]
    }
    inventory = {
        "users": [{"username": "target.admin", "dn": "CN=target.admin,DC=target,DC=example"}],
        "groups": [{"name": "IT", "members": ["CN=target.admin,DC=target,DC=example"]}],
    }
    chains = build_attack_chains(
        session,  # type: ignore[arg-type]
        postex_ops=postex_ops,
        adcs_findings=adcs_findings,
        wsus_ops=wsus_ops,
        postex_scan=None,
        inventory=inventory,
        dc_ip="192.168.10.130",
    )
    assert chains
    chain = chains[0]
    assert chain.chain_id == "dll_hijack_adcs_wsus_da"
    assert chain.steps[0].ready is True
    assert chain.steps[1].ready is True
