from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from admapper.analysis.attack_readiness import (
    AttackVector,
    PrerequisiteCheck,
    _human_users,
    _kerberos_clock,
    _lockout_loaded,
    _open_ports,
    _port_check,
    _valid_cred_users,
)
from admapper.creds.policy import filter_spray_targets
from admapper.models.spray import DomainLockoutPolicy
from admapper.models.user import UserRecord
from admapper.report.engagement import _load_json
from admapper.report.engagement_map import loot_clue_rows


@dataclass
class WorkspaceContext:
    ws_path: Path
    users: list[UserRecord]
    policy: DomainLockoutPolicy
    owned_users: list[str]
    ports: set[int] = field(default_factory=set)
    valid: set[str] = field(default_factory=set)
    owned: set[str] = field(default_factory=set)
    humans: list[UserRecord] = field(default_factory=list)
    has_scan: bool = False
    has_enum: bool = False
    has_loot: bool = False
    has_creds: bool = False
    has_acls: bool = False
    inv: dict[str, Any] = field(default_factory=dict)
    loot: dict[str, Any] = field(default_factory=dict)
    asrep_users: list[UserRecord] = field(default_factory=list)
    krb_users: list[UserRecord] = field(default_factory=list)
    eligible_spray: list[str] = field(default_factory=list)
    skipped_spray: list[str] = field(default_factory=list)
    clues: list[dict[str, str]] = field(default_factory=list)

    @classmethod
    def build(
        cls,
        ws_path: Path,
        *,
        users: list[UserRecord],
        policy: DomainLockoutPolicy,
        owned_users: list[str] | None = None,
    ) -> WorkspaceContext:
        ws_path = Path(ws_path)
        owned = {u.lower().rstrip("$") for u in (owned_users or [])}
        valid = _valid_cred_users(ws_path)
        inv = _load_json(ws_path / "auth_inventory.json") or {}
        loot = _load_json(ws_path / "loot_manifest.json") or {}
        ports = _open_ports(ws_path)
        humans = _human_users(users)
        eligible, skipped = filter_spray_targets(humans, policy)
        return cls(
            ws_path=ws_path,
            users=users,
            policy=policy,
            owned_users=list(owned_users or []),
            ports=ports,
            valid=valid,
            owned=owned,
            humans=humans,
            has_scan=bool((_load_json(ws_path / "unauth_scan.json") or {}).get("hosts")),
            has_enum=bool(inv.get("users")),
            has_loot=bool(loot.get("file_count")) or bool(loot.get("parsed_credentials")),
            has_creds=bool(valid),
            has_acls=bool((_load_json(ws_path / "acl_findings.json") or {}).get("findings")),
            inv=inv,
            loot=loot,
            asrep_users=[u for u in humans if u.asrep_roastable and u.enabled],
            krb_users=[u for u in humans if u.kerberoastable and u.enabled],
            eligible_spray=eligible,
            skipped_spray=skipped,
            clues=loot_clue_rows(ws_path),
        )


def _vec(
    attack_id: str,
    title: str,
    phase: str,
    prereqs: list[PrerequisiteCheck],
    *,
    ready: bool | None = None,
    targets: list[dict[str, Any]] | None = None,
    note: str = "",
) -> AttackVector:
    met = ready if ready is not None else all(p.met for p in prereqs)
    return AttackVector(
        attack_id=attack_id,
        title=title,
        phase=phase,
        ready=met,
        prerequisites=prereqs,
        targets=targets or [],
        note=note,
    )


def _has_delegation(ctx: WorkspaceContext, kind: str) -> bool:
    kerb = _load_json(ctx.ws_path / "kerberos_ops.json") or {}
    for op in kerb.get("operations") or []:
        if kind in str(op.get("technique", "")).lower():
            return True
    deleg = ctx.inv.get("delegations") or []
    for d in deleg:
        if kind in str(d.get("type", "")).lower():
            return True
    computers = ctx.inv.get("computers") or []
    for c in computers:
        uac = int(c.get("uac") or 0)
        if kind == "unconstrained" and uac & 0x80000:
            return True
        if kind == "constrained" and c.get("allowed_to_delegate"):
            return True
        if kind == "rbcd" and c.get("allowed_to_act"):
            return True
    return False


def _acl_right_present(ctx: WorkspaceContext, right: str) -> list[dict[str, Any]]:
    findings = (_load_json(ctx.ws_path / "acl_findings.json") or {}).get("findings") or []
    rl = right.lower()
    return [f for f in findings if str(f.get("right", "")).lower() == rl]


def _adcs_present(ctx: WorkspaceContext) -> bool:
    return bool(
        (_load_json(ctx.ws_path / "adcs_findings.json") or {}).get("findings")
        or ctx.inv.get("adcs")
        or (_load_json(ctx.ws_path / "adcs_inventory.json") or {}).get("templates")
    )


def _mssql_present(ctx: WorkspaceContext) -> bool:
    unauth = _load_json(ctx.ws_path / "unauth_scan.json") or {}
    for host in unauth.get("hosts") or []:
        for p in host.get("open_ports") or []:
            if int(p) == 1433:
                return True
    postex = _load_json(ctx.ws_path / "postex_findings.json") or {}
    return bool(postex.get("mssql_instances"))


def build_all_attack_vectors(ctx: WorkspaceContext) -> list[AttackVector]:
    """Generic AD pentest vectors — workspace facts only, no lab assumptions."""
    vectors: list[AttackVector] = []
    p = ctx.policy
    ws = ctx.ws_path

    # ── RECON ──
    vectors.append(
        _vec(
            "unauth_recon",
            "Recon sin autenticación",
            "recon",
            [
                PrerequisiteCheck("target_ip", "IP / scan completado", ctx.has_scan, "unauth_scan.json"),
                _port_check(ctx.ports, 389, "LDAP"),
                _port_check(ctx.ports, 88, "Kerberos KDC"),
                _port_check(ctx.ports, 445, "SMB"),
            ],
            note="DNS · SRV · superficie de servicios",
        )
    )
    vectors.append(
        _vec(
            "ldap_anonymous",
            "LDAP anónimo (RootDSE / enum)",
            "recon",
            [
                _port_check(ctx.ports, 389, "LDAP TCP/389"),
                PrerequisiteCheck("scan", "Scan previo", ctx.has_scan, "descubre DC y dominio"),
            ],
            note="Depende de GPO — puede estar deshabilitado",
        )
    )
    vectors.append(
        _vec(
            "smb_null_session",
            "SMB null session / guest",
            "recon",
            [
                _port_check(ctx.ports, 445, "SMB TCP/445"),
                PrerequisiteCheck("restrict_anon", "RestrictAnonymous no bloquea", False, "verificar manualmente"),
            ],
            note="GPP en SYSVOL si hay lectura",
        )
    )
    vectors.append(
        _vec(
            "samr_rid_enum",
            "SAMR / RID cycling",
            "recon",
            [
                _port_check(ctx.ports, 445, "SMB para SAMR pipe"),
                PrerequisiteCheck("user_list", "Lista parcial de usuarios", ctx.has_enum, "mejor con LDAP/SAMR"),
            ],
            note="Impacket lookupsid / enum4linux",
        )
    )
    vectors.append(
        _vec(
            "dns_enum",
            "Enumeración DNS / SRV",
            "recon",
            [
                PrerequisiteCheck("domain", "Nombre de dominio conocido", ctx.has_scan, "del scan o operador"),
            ],
            note="_ldap._tcp · _kerberos._tcp",
        )
    )

    # ── CREDENTIALS ──
    vectors.append(
        _vec(
            "asreproast",
            "AS-REP roasting",
            "creds",
            [
                _port_check(ctx.ports, 88, "Kerberos KDC"),
                PrerequisiteCheck("user_list", "Usuarios válidos", ctx.has_enum, f"{len(ctx.humans)} humanos"),
                PrerequisiteCheck("asrep_targets", "DONT_REQ_PREAUTH", bool(ctx.asrep_users), f"{len(ctx.asrep_users)} cuenta(s)"),
            ],
            targets=[{"username": u.username} for u in ctx.asrep_users[:10]],
            note="Sin lockout — hash offline",
        )
    )
    vectors.append(
        _vec(
            "kerberoast",
            "Kerberoasting",
            "creds",
            [
                _port_check(ctx.ports, 88, "Kerberos KDC"),
                PrerequisiteCheck("spn_targets", "Cuentas con SPN", bool(ctx.krb_users), f"{len(ctx.krb_users)}"),
                PrerequisiteCheck("valid_cred", "Credencial para pre-auth", ctx.has_creds, "cualquier bind válido"),
                _kerberos_clock(ws),
            ],
            targets=[{"username": u.username, "spns": len(u.spns)} for u in ctx.krb_users[:10]],
        )
    )
    vectors.append(
        _vec(
            "timeroasting",
            "Timeroasting",
            "creds",
            [
                PrerequisiteCheck("valid_cred", "LDAP autenticado", ctx.has_creds, ""),
                PrerequisiteCheck("computers", "Inventario de equipos", bool(ctx.inv.get("computers")), "auth_inventory"),
                _port_check(ctx.ports, 389, "LDAP"),
            ],
            note="Crack offline machine AES keys",
        )
    )
    spray_prereqs = [
        _lockout_loaded(ws, p),
        PrerequisiteCheck("user_list", "Usuarios enumerados", ctx.has_enum, f"{len(ctx.humans)} humanos"),
        PrerequisiteCheck("spray_eligible", "Bajo umbral lockout", bool(ctx.eligible_spray), f"{len(ctx.eligible_spray)} elegibles"),
        _port_check(ctx.ports, 389, "LDAP spray"),
        PrerequisiteCheck("operator_pwd", "Contraseña elegida por operador", False, "revisa reglas de pista"),
    ]
    vectors.append(
        _vec(
            "passwordspray",
            "Password spraying",
            "creds",
            spray_prereqs,
            ready=all(x.met for x in spray_prereqs[:-1]),
            targets=[{"username": u} for u in ctx.eligible_spray[:15]],
            note="Un password por ronda — respeta ventana GPO",
        )
    )
    vectors.append(
        _vec(
            "gpp_cpassword",
            "GPP cpassword (SYSVOL)",
            "creds",
            [
                _port_check(ctx.ports, 445, "SMB SYSVOL"),
                PrerequisiteCheck("read_share", "Lectura SYSVOL o share", ctx.has_loot, "loot SMB o acceso manual"),
            ],
            note="Groups.xml con cpassword AES",
        )
    )
    vectors.append(
        _vec(
            "blank_password",
            "Cuentas sin contraseña / pwd not required",
            "creds",
            [
                PrerequisiteCheck("targets", "UAC PASSWD_NOTREQD", any(u.password_not_required for u in ctx.humans), "del inventario LDAP"),
                _port_check(ctx.ports, 389, "LDAP bind"),
            ],
        )
    )

    # Loot verify — per clue
    from admapper.analysis.attack_readiness import _attempts_remaining

    by_name = {u.username.lower(): u for u in ctx.humans}
    for clue in ctx.clues:
        user = str(clue.get("user", ""))
        if not user or user.lower() in ctx.valid:
            continue
        target_rec = by_name.get(user.lower())
        remaining = _attempts_remaining(target_rec, p) if target_rec else None
        locked = bool(target_rec and target_rec.lockout_time and target_rec.lockout_time != 0)
        vectors.append(
            _vec(
                f"creds_verify:{user.lower()}",
                f"Verificar credencial — {user}",
                "creds",
                [
                    _lockout_loaded(ws, p),
                    PrerequisiteCheck("target_exists", f"{user} en inventario", target_rec is not None, ""),
                    PrerequisiteCheck("not_locked", "Cuenta no bloqueada", not locked, ""),
                    PrerequisiteCheck("attempts", "Intentos restantes > 0", remaining is None or remaining > 0, f"restantes={remaining}"),
                    _port_check(ctx.ports, 389, "LDAP verify"),
                    _kerberos_clock(ws),
                    PrerequisiteCheck("operator_pwd", "Contraseña del operador", False, f"pista: «{clue.get('string', '')[:36]}»"),
                ],
                ready=target_rec is not None and not locked and (remaining is None or remaining > 0) and _load_json(ws / "lockout_policy.json") is not None,
                targets=[{"username": user, "attempts_remaining": remaining}],
                note="Lockout ANTES del bind — aplica reglas de pista",
            )
        )

    # ── ENUM ──
    vectors.append(
        _vec(
            "ldap_enum",
            "Enumeración LDAP autenticada",
            "enum",
            [
                PrerequisiteCheck("valid_cred", "Credencial válida", ctx.has_creds, ", ".join(sorted(ctx.valid))[:60]),
                _port_check(ctx.ports, 389, "LDAP"),
            ],
            ready=ctx.has_creds and not ctx.has_enum,
            note="Persiste auth_inventory + lockout_policy",
        )
    )
    vectors.append(
        _vec(
            "bloodhound_collect",
            "BloodHound / SharpHound",
            "enum",
            [
                PrerequisiteCheck("valid_cred", "Credencial", ctx.has_creds, ""),
                PrerequisiteCheck("enum", "Inventario base", ctx.has_enum, "opcional pero recomendado"),
            ],
            note="ACL · delegación · paths a DA",
        )
    )
    vectors.append(
        _vec(
            "trust_enum",
            "Enumeración de trusts",
            "enum",
            [
                PrerequisiteCheck("valid_cred", "Credencial de dominio", ctx.has_creds, ""),
                PrerequisiteCheck("enum", "LDAP autenticado", ctx.has_enum, ""),
            ],
        )
    )

    # ── LOOT ──
    vectors.append(
        _vec(
            "smb_loot",
            "Loot SMB / shares",
            "loot",
            [
                PrerequisiteCheck("valid_cred", "Credencial SMB/LDAP", ctx.has_creds, ""),
                _port_check(ctx.ports, 445, "SMB"),
            ],
            targets=[{"files": ctx.loot.get("file_count", 0)}] if ctx.has_loot else [],
        )
    )

    # ── KERBEROS ADVANCED ──
    vectors.append(
        _vec(
            "unconstrained_delegation",
            "Delegación sin restricciones",
            "kerberos",
            [
                PrerequisiteCheck("valid_cred", "Credencial", ctx.has_creds, ""),
                PrerequisiteCheck("deleg_hosts", "Equipos TRUSTED_FOR_DELEGATION", _has_delegation(ctx, "unconstrained"), "kerberos_ops o inventario"),
                PrerequisiteCheck("coerce", "Coerción de auth al listener", False, "PetitPotam / printerbug"),
            ],
            note="Captura TGT en equipo delegado",
        )
    )
    vectors.append(
        _vec(
            "constrained_delegation",
            "Delegación restringida (S4U)",
            "kerberos",
            [
                PrerequisiteCheck("valid_cred", "Cred de cuenta delegada", ctx.has_creds, ""),
                PrerequisiteCheck("s4u", "msDS-AllowedToDelegateTo", _has_delegation(ctx, "constrained"), ""),
                _kerberos_clock(ws),
            ],
        )
    )
    vectors.append(
        _vec(
            "rbcd_abuse",
            "RBCD (Resource-Based)",
            "kerberos",
            [
                PrerequisiteCheck("valid_cred", "Credencial", ctx.has_creds, ""),
                PrerequisiteCheck("genericwrite", "GenericWrite sobre equipo O MAQ>0", bool(_acl_right_present(ctx, "genericwrite")) or bool(ctx.inv.get("machine_account_quota")), "ACL o MAQ"),
                _kerberos_clock(ws),
            ],
            note="getST impersonation",
        )
    )
    vectors.append(
        _vec(
            "shadow_credentials",
            "Shadow Credentials",
            "kerberos",
            [
                PrerequisiteCheck("acl", "GenericAll/GenericWrite sobre usuario", bool(_acl_right_present(ctx, "genericall") or _acl_right_present(ctx, "genericwrite")), "acl_findings"),
                PrerequisiteCheck("valid_cred", "Cred del principal con derecho", bool(ctx.owned & ctx.valid), ""),
            ],
            note="msDS-KeyCredentialLink — pywhisker",
        )
    )

    # ── ACL ABUSE (generic per right) ──
    acl_rights = [
        ("genericall_abuse", "GenericAll", "genericall", "Control total — reset/shadow/addmember"),
        ("writedacl_abuse", "WriteDACL", "writedacl", "ACE injection → GenericAll o DCSync"),
        ("writeowner_abuse", "WriteOwner", "writeowner", "Ownership → WriteDACL"),
        ("genericwrite_abuse", "GenericWrite", "genericwrite", "Atributos — RBCD, gMSA, SPN"),
        ("forcechangepassword", "ForceChangePassword", "forcechangepassword", "Reset sin pwd actual"),
        ("addmember_abuse", "AddMember / Self", "addmember", "Unirse a grupo privilegiado"),
        ("readgmsapassword", "ReadGMSAPassword", "readgmsapassword", "Credencial gMSA"),
        ("readlapspassword", "ReadLAPSPassword", "readlapspassword", "LAPS password"),
        ("writespn_abuse", "WriteSPN", "writespn", "Kerberoast forzado"),
        ("dcsync_abuse", "DCSync", "dcsync", "Replicación de secretos AD"),
    ]
    for aid, title, right, desc in acl_rights:
        hits = _acl_right_present(ctx, right)
        pivot_ok = any(str(f.get("principal", "")).lower() in ctx.owned & ctx.valid for f in hits)
        vectors.append(
            _vec(
                aid,
                f"ACL — {title}",
                "escalate",
                [
                    PrerequisiteCheck("acl_enum", "ACL enumerada", ctx.has_acls, f"{len(hits)} ACE(s) {right}"),
                    PrerequisiteCheck("pivot_cred", "Principal owned + cred válida", pivot_ok, "compromete al trustee"),
                    _port_check(ctx.ports, 389, "LDAP modify"),
                ],
                ready=bool(hits) and pivot_ok,
                targets=[{"principal": f.get("principal"), "target": f.get("target_name")} for f in hits[:5]],
                note=desc,
            )
        )

    vectors.append(
        _vec(
            "acl_enum",
            "Enumerar ACLs (owned)",
            "escalate",
            [
                PrerequisiteCheck("owned_cred", "Owned + cred válida", bool(ctx.owned & ctx.valid), ""),
                _port_check(ctx.ports, 389, "LDAP"),
                PrerequisiteCheck("enum", "Inventario AD", ctx.has_enum, ""),
            ],
        )
    )

    # ── AD CS ──
    vectors.append(
        _vec(
            "adcs_enum",
            "Enumeración AD CS",
            "escalate",
            [
                PrerequisiteCheck("valid_cred", "Credencial", ctx.has_creds, ""),
                PrerequisiteCheck("adcs", "CA / templates en LDAP", _adcs_present(ctx), "adcs find"),
                _port_check(ctx.ports, 389, "LDAP"),
            ],
        )
    )
    vectors.append(
        _vec(
            "adcs_esc_enrollment",
            "AD CS ESC — enrollment",
            "escalate",
            [
                PrerequisiteCheck("adcs", "Template vulnerable", _adcs_present(ctx), ""),
                PrerequisiteCheck("enroll", "Derecho de enrollment", False, "certipy find -vulnerable"),
            ],
            note="ESC1–ESC16 según misconfig",
        )
    )

    # ── LATERAL ──
    vectors.append(
        _vec(
            "pass_the_hash",
            "Pass-the-Hash",
            "lateral",
            [
                PrerequisiteCheck("hash", "Hash NT recuperado", bool((_load_json(ws / "credentials.json") or {}).get("hashes")), "roast/dcsync/lsa"),
                _port_check(ctx.ports, 445, "SMB"),
            ],
        )
    )
    vectors.append(
        _vec(
            "pass_the_ticket",
            "Pass-the-Ticket",
            "lateral",
            [
                PrerequisiteCheck("ticket", "TGT/TGS exportado", False, "Rubeus / mimikatz"),
                _port_check(ctx.ports, 88, "Kerberos"),
            ],
        )
    )
    vectors.append(
        _vec(
            "winrm_lateral",
            "WinRM lateral",
            "lateral",
            [
                PrerequisiteCheck("valid_cred", "Credencial admin/local", ctx.has_creds, ""),
                _port_check(ctx.ports, 5985, "WinRM HTTP"),
            ],
            note="5986 si HTTPS",
        )
    )
    vectors.append(
        _vec(
            "rdp_lateral",
            "RDP lateral",
            "lateral",
            [
                PrerequisiteCheck("valid_cred", "Credencial", ctx.has_creds, ""),
                _port_check(ctx.ports, 3389, "RDP"),
            ],
        )
    )
    vectors.append(
        _vec(
            "mssql_linked",
            "MSSQL impersonate / linked",
            "lateral",
            [
                PrerequisiteCheck("mssql", "Instancia MSSQL", _mssql_present(ctx), "1433 o postex"),
                PrerequisiteCheck("valid_cred", "Credencial SQL o Windows", ctx.has_creds, ""),
            ],
        )
    )

    # ── COERCION ──
    vectors.append(
        _vec(
            "petitpotam_coerce",
            "Coerción (PetitPotam / PrinterBug)",
            "coerce",
            [
                PrerequisiteCheck("listener", "NTLM relay / listener", False, "ntlmrelayx configurado"),
                PrerequisiteCheck("target", "DC o spooler alcanzable", ctx.has_scan, ""),
            ],
            note="Relay → LDAP RBCD o AD CS ESC8",
        )
    )
    vectors.append(
        _vec(
            "ntlm_relay",
            "NTLM relay",
            "coerce",
            [
                PrerequisiteCheck("coerce", "Auth coaccionada hacia atacante", False, ""),
                PrerequisiteCheck("signing", "LDAP/SMB signing no obligatorio", False, "verificar manualmente"),
            ],
        )
    )

    # ── POST-EX ──
    vectors.append(
        _vec(
            "dump_lsa",
            "Dump LSA / SAM (host)",
            "postex",
            [
                PrerequisiteCheck("admin", "Admin local / SYSTEM en host", bool(ctx.owned), "postex scan"),
            ],
        )
    )
    vectors.append(
        _vec(
            "golden_ticket",
            "Golden Ticket",
            "postex",
            [
                PrerequisiteCheck("krbtgt", "Hash krbtgt", False, "requiere DCSync o DC compromise"),
            ],
        )
    )

    # ── CVE modules ──
    vectors.append(
        _vec(
            "nopac",
            "noPac (CVE-2021-42278)",
            "escalate",
            [
                PrerequisiteCheck("valid_cred", "Credencial", ctx.has_creds, ""),
                PrerequisiteCheck("maq", "MAQ > 0", bool(ctx.inv.get("machine_account_quota")), "LDAP domain policy"),
            ],
        )
    )

    # WSUS / ADCS from workspace
    for op in (_load_json(ws / "wsus_ops.json") or {}).get("operations") or []:
        prereqs = [
            PrerequisiteCheck(str(p.get("key", "")), str(p.get("label", "")), bool(p.get("met")), str(p.get("detail", "")))
            for p in (op.get("prerequisites") or [])
        ]
        vectors.append(
            AttackVector(
                attack_id=f"wsus:{op.get('technique', 'wsus')}",
                title=str(op.get("title") or "WSUS"),
                phase="escalate",
                ready=bool(op.get("prerequisites_met")),
                prerequisites=prereqs,
                targets=[],
                note="Módulo WSUS",
            )
        )

    return vectors
