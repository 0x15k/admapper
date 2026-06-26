from admapper.adcs.enroll import (
    EnrollProfile,
    build_cert_request_inf,
    parse_enroll_log,
)


def test_update_srv_user_context_uses_empty_subject_and_san_dns() -> None:
    profile = EnrollProfile.from_template(
        template="UpdateSrv",
        dns_name="dc01.corp.local",
        ca_host="dc01.corp.local",
        ca_name="corp-DC01-CA",
    )
    inf = build_cert_request_inf(profile)
    assert "Subject = " in inf
    assert "CN=dc01.corp.local" not in inf.split("[Extensions]")[0]
    assert "dns=dc01.corp.local" in inf
    assert "MachineKeySet = FALSE" in inf


def test_machine_template_uses_machine_keyset() -> None:
    from admapper.adcs.constants import CT_FLAG_MACHINE_TYPE

    profile = EnrollProfile.from_template(
        template="Machine",
        dns_name="host.corp.local",
        ca_host="dc01.corp.local",
        ca_name="corp-DC01-CA",
        enrollment_flags=CT_FLAG_MACHINE_TYPE,
    )
    inf = build_cert_request_inf(profile)
    assert "MachineKeySet = TRUE" in inf
    assert 'Subject = "CN=host.corp.local"' in inf


def test_wsus_esc1_uses_subject_cn_for_wsus_fqdn() -> None:
    profile = EnrollProfile(
        template="UpdateSrv",
        dns_name="dc01.corp.local",
        ca_host="dc01.corp.local",
        ca_name="corp-DC01-CA",
        machine_context=False,
        enrollee_supplies_subject=False,
        wsus_esc1_subject=True,
    )
    inf = build_cert_request_inf(profile)
    assert 'Subject = "CN=dc01.corp.local"' in inf
    assert "dns=dc01.corp.local" in inf
    assert "MachineKeySet = FALSE" in inf


def test_parse_enroll_log_detects_template_conflict() -> None:
    status = parse_enroll_log("User context template conflicts with machine context.")
    assert status.present is True
    assert status.success is False
    assert status.errors
