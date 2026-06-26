from __future__ import annotations

import os
import subprocess
from pathlib import Path

from admapper.support.platform import resolve_impacket_script, subprocess_run_kwargs


class TicketError(RuntimeError):
    pass


def _realm(domain: str) -> str:
    return domain.upper()


def winrm_host_candidates(domain: str, dc_fqdn: str | None) -> list[str]:
    """Try short hostname and DC01-style FQDN variants for WinRM SPNs."""
    domain_l = domain.lower().rstrip(".")
    candidates: list[str] = [domain_l]
    if dc_fqdn:
        host = dc_fqdn.rstrip(".")
        if host.lower() not in {c.lower() for c in candidates}:
            candidates.append(host)
        short = host.split(".", 1)[0]
        if short and short.lower() not in {c.lower() for c in candidates}:
            if "." in host:
                candidates.append(f"{short.lower()}.{domain_l}")
    return candidates


def winrm_spn_names(domain: str, dc_fqdn: str | None) -> list[str]:
    """Hostnames used in HTTP/WSMAN SPNs for WinRM."""
    names: list[str] = []
    for host in winrm_host_candidates(domain, dc_fqdn):
        names.append(host)
        short = host.split(".", 1)[0]
        if short.upper() not in {n.upper() for n in names}:
            names.append(short.upper())
    return names


def write_krb5_conf(path: Path, *, domain: str, dc_ip: str) -> None:
    realm = _realm(domain)
    path.write_text(
        f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    {realm} = {{
        kdc = {dc_ip}
        admin_server = {dc_ip}
    }}

[domain_realm]
    .{domain.lower()} = {realm}
    {domain.lower()} = {realm}
""",
        encoding="utf-8",
    )


def _mit_bin(name: str) -> str | None:
    from admapper.support.platform import resolve_mit_krb5_bin

    return resolve_mit_krb5_bin(name)


def klist_text(ccache: Path, krb5_conf: Path) -> str:
    klist = _mit_bin("klist")
    if not klist:
        return ""
    env = os.environ.copy()
    env["KRB5_CONFIG"] = str(krb5_conf)
    env["KRB5CCNAME"] = f"FILE:{ccache}"
    proc = subprocess.run([klist, "-e"], env=env, capture_output=True, text=True, check=False)
    return (proc.stdout or proc.stderr or "").strip()


def _mit_kinit_env(
    *,
    username: str,
    password: str,
    domain: str,
    dc_ip: str,
    ccache: Path,
    krb5_conf: Path,
    clock_skew: str | None = None,
) -> dict[str, str]:
    """Run kinit and return krb5 env for follow-up kvno/GSSAPI."""
    kinit = _mit_bin("kinit")
    kdestroy = _mit_bin("kdestroy")

    if not kinit:
        from admapper.support.platform import mit_krb5_install_hint

        raise TicketError(f"MIT krb5 not found — run: {mit_krb5_install_hint()}")

    write_krb5_conf(krb5_conf, domain=domain, dc_ip=dc_ip)
    realm = _realm(domain)
    principal = username if "@" in username else f"{username}@{realm}"

    env = os.environ.copy()
    env["KRB5_CONFIG"] = str(krb5_conf)
    env["KRB5CCNAME"] = f"FILE:{ccache}"

    if kdestroy:
        subprocess.run([kdestroy], env=env, capture_output=True, check=False)

    from admapper.support.platform import get_clock_skew, wrap_command_with_clock_skew

    skew = clock_skew or get_clock_skew()
    kinit_cmd = wrap_command_with_clock_skew([kinit, principal], clock_skew=skew)
    proc = subprocess.run(kinit_cmd, input=password.encode(), env=env, capture_output=True, check=False)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or b"").decode(errors="replace").strip()
        raise TicketError(f"kinit failed: {err or proc.returncode}")
    return env


def mit_kinit_tgt(
    *,
    username: str,
    password: str,
    domain: str,
    dc_ip: str,
    ccache: Path,
    krb5_conf: Path,
    clock_skew: str | None = None,
) -> None:
    """Acquire TGT only — LDAP GSSAPI (gMSA) without WinRM service tickets."""
    _mit_kinit_env(
        username=username,
        password=password,
        domain=domain,
        dc_ip=dc_ip,
        ccache=ccache,
        krb5_conf=krb5_conf,
        clock_skew=clock_skew,
    )


def mit_kinit(
    *,
    username: str,
    password: str,
    domain: str,
    dc_fqdn: str,
    dc_ip: str,
    ccache: Path,
    krb5_conf: Path,
    verbose: bool = False,
    clock_skew: str | None = None,
) -> list[str]:
    """Acquire TGT + HTTP/WSMAN tickets for all likely WinRM SPN hostnames."""
    kvno = _mit_bin("kvno")
    if not kvno:
        from admapper.support.platform import mit_krb5_install_hint

        raise TicketError(f"MIT krb5 not found — run: {mit_krb5_install_hint()}")

    from admapper.support.platform import get_clock_skew, wrap_command_with_clock_skew

    env = _mit_kinit_env(
        username=username,
        password=password,
        domain=domain,
        dc_ip=dc_ip,
        ccache=ccache,
        krb5_conf=krb5_conf,
        clock_skew=clock_skew,
    )
    skew = clock_skew or get_clock_skew()

    obtained: list[str] = []
    http_ok = False
    for name in winrm_spn_names(domain, dc_fqdn):
        for service in ("HTTP", "WSMAN"):
            spn = f"{service}/{name}"
            kvno_cmd = wrap_command_with_clock_skew([kvno, spn], clock_skew=skew)
            proc = subprocess.run(kvno_cmd, env=env, capture_output=True, check=False)
            if proc.returncode == 0:
                obtained.append(spn)
                if service == "HTTP":
                    http_ok = True
                if verbose:
                    print(f"  kvno OK: {spn}")
            elif verbose:
                err = (proc.stderr or proc.stdout or b"").decode(errors="replace").strip()
                print(f"  kvno skip {spn}: {err[:120]}")

    if not http_ok:
        raise TicketError(
            "no HTTP service ticket — tried: "
            + ", ".join(f"HTTP/{n}" for n in winrm_spn_names(domain, dc_fqdn))
        )
    return obtained


def impacket_tickets(
    *,
    username: str,
    password: str,
    domain: str,
    dc_fqdn: str,
    dc_ip: str,
    workdir: Path,
    clock_skew: str | None = None,
) -> Path:
    """getTGT + getST via Impacket; returns path to service-ticket ccache."""
    realm = _realm(domain)
    user_part = username.split("@")[0]
    tgt_path = workdir / f"{user_part}.ccache"

    identity = f"{domain.lower()}/{user_part}:{password}"
    get_tgt = resolve_impacket_script("getTGT")
    get_st = resolve_impacket_script("getST")

    def _run(cmd: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        if clock_skew and not env:
            from admapper.support.platform import wrap_command_with_clock_skew

            cmd = wrap_command_with_clock_skew(cmd, clock_skew=clock_skew)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=workdir,
            env=env or os.environ.copy(),
            **subprocess_run_kwargs(),
        )

    cmd_tgt = [*get_tgt, identity, "-dc-ip", dc_ip]
    proc = _run(cmd_tgt)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise TicketError(f"getTGT failed: {err or proc.returncode}")

    env = os.environ.copy()
    env["KRB5CCNAME"] = str(tgt_path.resolve())
    last_err = ""
    st_path: Path | None = None
    for name in winrm_spn_names(domain, dc_fqdn):
        spn = f"HTTP/{name}"
        cmd_st = [
            *get_st,
            "-k",
            "-no-pass",
            "-spn",
            spn,
            "-dc-ip",
            dc_ip,
            f"{realm}/{user_part}",
        ]
        proc = _run(cmd_st, env=env)
        if proc.returncode == 0:
            candidates = list(workdir.glob(f"{user_part}@HTTP*{realm}.ccache"))
            if candidates:
                return candidates[0]
            st_path = workdir / f"{user_part}@HTTP_{name}@{realm}.ccache"
            if st_path.is_file():
                return st_path
        last_err = (proc.stderr or proc.stdout or "").strip()

    raise TicketError(f"getST failed for all HTTP SPNs: {last_err}")


def default_ticket_dir() -> Path:
    path = Path.home() / ".admapper" / "winrm"
    path.mkdir(parents=True, exist_ok=True)
    return path
