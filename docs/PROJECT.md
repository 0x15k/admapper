# ADMapper — Active Directory Mapping & Pentesting

> Master project plan. Goal: replicate and exceed what [ADScan](https://github.com/ADScanPro/adscan) does, technique by technique, in order of dependencies.

**Status:** Phases 3, 8.8, 14 (DCSync/postex), PingCastle audits, CLI visual style system, privilege-free clock sync, and worker exception wrapping completed.  
**Analyzed Reference:** ADScan v9.x (code + documentation)  
**Last Update:** 2026-06-25

---

## 1. Vision

Build a **multi-platform** Active Directory pentesting CLI tool (macOS, Linux, Windows) that:

1. **Does the same as ADScan LITE** — enumeration, credentials, attack graph, guided exploitation.
2. **Is modular** — each technique is an independent module that builds on the previous ones.
3. **Does not depend on restrictive licenses** — custom code, permissive license (Apache 2.0 / MIT).
4. **Outperforms ADScan** in architecture, transparency, and extensibility (see §8).

Operator target flow:

```
DNS/SRV → recon without creds → user inventory → roast/spray →
auth → LDAP/SMB collection → graph → attack paths → guided exploitation
```

### Actual Operational Methodology

The tool follows a dependency order designed not to bypass context:

1. **Bootstrap / discovery**
   - `set hosts <dc>`
   - `start_unauth`
   - Discovers domain, DC, ports, anonymous LDAP, SMB, SPNs, GMSA, and initial signals.
2. **User Recon**
   - `enum users`
   - Consolidates human inventory + service accounts + roast signals.
3. **Credentials**
   - `creds add`
   - `creds verify`
   - `asreproast`, `kerberoast`, `spray`
4. **Authentication / Expanded Collection**
   - `start_auth`
   - `enum auth`
   - `acls`
   - `adcs`
   - `coerce`
   - `mssql`
5. **Pivot / Post-Exploitation**
   - `exploit`
   - `pivot`
   - `winrm`
   - `postex`
6. **Synthesis**
   - `paths`
   - `brief`
   - `export`

### CLI ↔ GUI Mapping

The web UI is simply a frontend for the CLI engine. It must reflect the same order:

| GUI | Real CLI |
|---|---|
| `Scan` | `set hosts` + `start_unauth` |
| `Authenticate` | `creds add` + `creds verify` + `start_auth` |
| `Enum Users` | `enum users` |
| `AS-REP Roast` | `asreproast` |
| `Kerberoast` | `kerberoast` |
| `Spray` | `spray <password>` |
| `ACLs` | `acls` |
| `ADCS` | `adcs` |
| `Coerce` | `coerce` |
| `Exploit` | `exploit` |
| `Pivot` | `pivot <user>` |
| `WinRM` | `winrm <account>` |
| `Brief` | `brief` |

### Consistency Criteria

For CLI and GUI to be considered aligned, each web action must:

- invoke the same CLI command;
- persist the same workspace;
- produce the same artifacts (`users.json`, `credentials.json`, `graph.json`, `paths.json`, `findings.json`);
- reflect the same visual progress without re-implementing the technique on the web.

---

## 2. Language Choice

### Recommendation: **Python 3.11+** (main orchestrator)

| Criterion | Python | Go | Rust | Ruby |
|---|---|---|---|---|
| Existing AD Ecosystem | ★★★★★ Impacket, NetExec, Certipy, BloodHound, ldap3, krb libs | ★★☆☆☆ few mature libs | ★★☆☆☆ reimplement protocols | ★☆☆☆☆ almost none |
| Development Speed | ★★★★★ | ★★★☆☆ | ★★☆☆☆ | ★★★★☆ |
| Integrating External Tools | ★★★★★ native subprocess | ★★★★☆ | ★★★☆☆ | ★★★☆☆ |
| Interactive CLI (REPL) | ★★★★★ cmd/prompt_toolkit | ★★★☆☆ cobra without rich REPL | ★★☆☆☆ | ★★★★☆ |
| Single-binary Distribution | ★★☆☆☆ (PyInstaller/Nuitka) | ★★★★★ | ★★★★★ | ★★☆☆☆ |
| Massive Network Performance | ★★★☆☆ | ★★★★★ | ★★★★★ | ★★★☆☆ |
| Parsing LDAP/Kerberos/SMB | ★★★★★ battle-tested libs | ★★★☆☆ | ★★★★☆ (with effort) | ★★☆☆☆ |
| Pentester Learning Curve | ★★★★★ already used by all | ★★★☆☆ | ★★☆☆☆ | ★★☆☆☆ |

### Why Python over others

**ADScan has already proven the model:** Python orchestrating Docker + Impacket + NetExec + badldap + kerbad + aiosmb. 90% of the value is not in reinventing Kerberos, but in **chaining** stateful techniques (workspaces, credentials, graph).

- **Go** would be ideal for a network scanner or a portable binary, but would require reimplementing or wrapping a large part of the AD stack in CGo. Functional parity would take 3–5× longer to develop.
- **Rust** provides safety and performance, but the offensive AD ecosystem is immature. It only makes sense for performance-critical modules (future phase).
- **Ruby** lacks critical mass in AD pentesting.

### Future Hybrid Architecture (optional, phase 3+)

```
┌─────────────────────────────────────────┐
│  Python — CLI, orchestration, graph, UX │
├─────────────────────────────────────────┤
│  Wrappers — Impacket, NetExec, Certipy  │
├─────────────────────────────────────────┤
│  Go/Rust (future) — massive port scan,  │
│  distributed hash cracking, collectors  │
└─────────────────────────────────────────┘
```

### Selected Technical Stack

| Layer | Technology |
|---|---|
| Language | Python ≥ 3.11 |
| CLI / REPL | `typer` + `prompt_toolkit` (autocomplete, history) |
| Output | `rich` (tables, panels, progress) |
| LDAP | `ldap3` (sync) → migrate to async if needed |
| Kerberos | `impacket` / `kerbad` |
| SMB | `impacket` + `smbprotocol` / NetExec subprocess |
| DNS | `dnspython` |
| Graph | Custom JSON + BloodHound CE export |
| State | JSON per workspace (like ADScan) |
| Tests | `pytest` |
| Lint | `ruff` |
| Packaging | `uv` / `pipx` |

### Compatibility — Python model (not native binary)

ADMapper is distributed as a **pip package** with entry point `admapper`. Requires Python 3.11+; it is not a single-executable package like PyInstaller (that would be a later phase).

**Three tiers** — see full analysis in **`docs/COMPATIBILITY.md`**:

| Tier | Installation | Capabilities |
|---|---|---|
| **CORE** | `pip install admapper` | CLI, DNS, ports, LDAP enum/spray/verify, workspaces JSON |
| **RECON** | `pip install admapper[recon]` | Impacket: SAMR, RID, SMB, AS-REP, Kerberoast, verify SMB/KRB |
| **EXTERNAL** | User (brew/apt/PATH) | hashcat, john, kerbrute, nxc — **not included in the package** |

Real cross-platform guarantee: **everything in CORE + RECON** uses Python/`sys.executable` — same code on macOS, Linux, and Windows. The EXTERNAL tier depends on OS binaries.

| Platform | Priority | Typical Installation |
|---|---|---|
| **macOS** | ★★★★★ | venv + `pip install -e ".[recon]"` — development environment |
| **Linux** | ★★★★★ | Kali/Debian + pip; wordlists in `/usr/share/wordlists` |
| **Windows** | ★★★★☆ | active venv; Impacket in `Scripts\`; LDAP spray without extras |

**Modules:** `admapper/core/platform.py` (PATH, subprocess), `admapper/core/compatibility.py` (matrix by command).

**Diagnostics:** `platform` command in the shell.

Guides: **`docs/COMPATIBILITY.md`** (analysis) · **`docs/PLATFORMS.md`** (installation by OS)

---

## 3. Project Architecture

### Directory Structure

```
admapper/
├── admapper/                      # Main package
│   ├── core/                  # Session, workspace, paths, credentials store, output
│   ├── models/                # Dataclasses (Credential, UserRecord, …)
│   ├── methodology/           # Canonical engagement phases (P1–P12)
│   ├── analysis/              # Operator intel: readiness, vectors, user_match, password rules
│   ├── cli/                   # Typer entrypoints and shell dispatch
│   ├── recon/                 # Unauthenticated discovery
│   ├── enumeration/           # User enumeration (SAMR, LDAP)
│   ├── creds/                 # Roast, spray, verify, Kerberos skew
│   ├── auth/                  # Authenticated LDAP/SMB enum, BloodHound export
│   ├── graph/                 # Attack graph + dashboard UI (ops_payload, ops_html, dashboard_server)
│   ├── exploit/               # Chained credentials / exploit engine
│   ├── escalate/              # Pivot and next-hop edges
│   ├── engage/                # Auto-engagement & task execution orchestration
│   ├── chain/                 # Automated exploit chain analysis
│   ├── guides/                # Manual technique catalog and pentest book
│   ├── report/                # Engagement map, export, MITRE Navigator
│   └── <technique>/           # Specific modules: acl, adcs, kerberos, coerce, cves, mssql, postex, wsus, winrm
├── workspaces/                # engagement data (gitignored)
├── tests/                     # unit and integration tests
├── docs/                      # documentation
├── pyproject.toml
└── README.md
```

Each specific technique package (`<technique>/`) typically provides:
- `analyze.py`: Analysis of workspace findings based on JSON artifacts.
- `catalog.py`: Technique metadata and MITRE ATT&CK identifiers.
- `render.py`: Rendering functions for console output (CLI).

### Data Flow

1. **Workspace** (`~/.admapper/workspaces/<name>/` by default) contains only JSON artifacts of the active engagement. These data files should never be checked into version control.
2. The **Scan/Run** commands write serialized states such as `unauth_scan.json`, `credentials.json`, `auth_inventory.json`, etc.
3. The **Analysis** engine consumes these artifacts to build the operational payload (`ops_payload`), attack vectors, and general engagement intelligence.
4. The **Dashboard** command (`admapper dashboard` / `admapper g`) exposes the local HTTP server for the interactive web UI and allows triggering CLI subprocesses in real-time.

### Pentest Phases

Mapped into a canonical model centralized in `admapper/methodology/unified.py` (Phases P1 to P12). The frontend's interactive bar exposes 9 consolidated steps mapped directly to these phases.

### Security and Secrets

- Credentials and hashes are stored in plaintext by design in `credentials.json` under the operator's workspace (local machine).
- All generated reports or dynamic HTML files (`ad_ops.html`, `attack_graph.html`) must be stored exclusively inside the workspace directory to prevent leaks.
- The dashboard server masks secrets in JSON transmissions and console outputs. Raw credentials must not be embedded in payloads transmitted to the frontend.

### Design Principles

1. **One module = one technique** with a uniform interface: `discover() → execute() → export()`.
2. **Explicit State** — each module reads/writes JSON artifacts in the workspace.
3. **Confirmation before noisy actions** — spraying, massive roasting, DCSync, etc.
4. **No mandatory Docker** — pip dependencies; Docker optional for labs.
5. **Mocked Tests** — does not require a real AD domain for CI.
6. **Manual exploitation guide for each technique** — like BloodHound "Abuse":
   catalog in `admapper/guides/catalog.py`, rendered after each finding,
   `guide <technique>` command to query at any time.
   Each entry includes: prerequisites, manual steps, copy-paste commands,
   tools, MITRE ID, and next steps in ADMapper.

### Workspace (Artifacts by Domain)

```
workspaces/<engagement>/<domain>/
├── config.json              # DCs, realm, options
├── hosts.json               # hosts inventory
├── users.json               # unified user inventory
├── credentials.json         # verified creds (user/hash/ticket)
├── findings.json            # findings with severity + MITRE
├── kerberoast_hashes.json
├── asreproast_hashes.json
├── spray_history.json
├── graph.json               # native attack graph
└── bloodhound/              # BH CE compatible export
```

---

## 4. Roadmap — WHAT WE DO NOW

Phases are ordered by **dependency**: each one consumes the output of the previous ones and enables the next.

---

### Phase 0 — Project Foundation

> Without this, nothing else works. Absolute first priority.

| ID | Task | Deliverable | Status |
|---|---|---|---|
| 0.1 | Initialize `pyproject.toml`, package structure, `uv`/`pip` | Compilable repo | ✅ |
| 0.2 | Base CLI: `admapper start` opens interactive shell | REPL with prompt | ✅ |
| 0.3 | Workspaces system: `set workspace <name>`, `set domain <fqdn>` | JSON persistence | ✅ |
| 0.4 | Output module (`rich`): tables, banners, red/yellow/green alerts | Consistent UX | ✅ |
| 0.5 | Credentials store: add/list/verify structure | `credentials.json` | ✅ |
| 0.6 | Global config: `~/.admapper/config.json` | Operator preferences | ✅ |
| 0.7 | Operation modes: `auto` / `semi` / `manual` | Workspace flag | ✅ |
| 0.8 | Base tests + CI (ruff, pytest) | Minimum pipeline | ✅ |

**Done Criteria:** `admapper start` → create workspace → save config → exit → reopen and recover state.

---

### Phase 1 — Reconnaissance without credentials (DNS + services)

> First real technique. Discovers the domain and the DCs.

| ID | Task | Equivalent ADScan Technique | MITRE | Status |
|---|---|---|---|---|
| 1.1 | DNS Resolution: SRV `_ldap._tcp`, `_kerberos._tcp`, `_gc._tcp` | DNS enumeration | T1018 | ✅ |
| 1.2 | Domain inference from IP/range (`set hosts`) | Domain discovery | T1018 | ✅ |
| 1.3 | LDAP Probe: anonymous bind, RootDSE, naming contexts | LDAP anonymous | T1087.002 | ✅ |
| 1.4 | SMB Probe: null session, guest, signing required | SMB null session | T1021.002 | ✅ |
| 1.5 | Kerberos Probe: realm, KDC reachable | Kerberos enum | T1558 | ✅ |
| 1.6 | Service discovery in range (ports 88, 389, 445, 5985, 1433) | Port scan | T1046 | ✅ |
| 1.7 | Command: `start_unauth` orchestrates 1.1–1.6 | Unauth workflow | — | ✅ |
| 1.8 | Export findings to `findings.json` | Evidence export | — | ✅ |

**Depends on:** Phase 0  
**Enables:** Phase 2, 3  
**Done Criteria:** With only an IP range, discover domain FQDN, DCs list, and whether anonymous LDAP / SMB null are open.

---

### Phase 2 — User enumeration (SAMR + LDAP + RID)

> We need usernames before roasting or spraying.

| ID | Task | Equivalent ADScan Technique | MITRE | Status |
|---|---|---|---|---|
| 2.1 | SAMR `SamrEnumerateUsersInDomain` via SMB null session | SAMR enumeration | T1087.002 | ✅ |
| 2.2 | LDAP anonymous: `(objectClass=user)` filter if anon bind works | LDAP user enum | T1087.002 | ✅ |
| 2.3 | RID cycling (LSARPC) as fallback when SAMR fails | RID cycling | T1087.002 | ✅ |
| 2.4 | Merge sources → unified `users.json` with `sources[]` | Unified inventory | — | ✅ |
| 2.5 | Extract SAMR/LDAP descriptions (sensitive keywords) | User descriptions | T1087.002 | ✅ |
| 2.6 | Filter machine accounts (`$`) vs humans | User classification | — | ✅ |

**Depends on:** Phase 1 (DC + SMB/LDAP reachable)  
**Enables:** Phases 3, 4, 5  
**Done Criteria:** List of ≥1 real domain user discovered without credentials, with traceable source.

---

### Phase 3 — Detection of roastable accounts

> Identify targets before requesting tickets (low noise).

| ID | Task | Equivalent ADScan Technique | MITRE | Status |
|---|---|---|---|---|
| 3.1 | Detect `DONT_REQ_PREAUTH` (UAC 0x400000) via LDAP | AS-REP target ID | T1558.004 | ✅ |
| 3.2 | Detect accounts with SPN (exclude krbtgt, machine accounts optional) | Kerberoast target ID | T1558.003 | ✅ |
| 3.3 | Mark users in `users.json` with flags `asrep_roastable`, `kerberoastable` | Inventory metadata | — | ✅ |
| 3.4 | Detect `UF_DONT_REQUIRE_PREAUTH` without LDAP (UserAccountControl via SAMR) | SAMR fallback | T1558.004 | ✅ |

**Depends on:** Phase 2  
**Enables:** Phases 4, 5  
**Done Criteria:** Report of roastable accounts before requesting any tickets.

---

### Phase 4 — AS-REP Roasting

> First offline credential collection technique.

| ID | Task | Equivalent ADScan Technique | MITRE | Status |
|---|---|---|---|---|
| 4.1 | Request AS-REP for `DONT_REQ_PREAUTH` accounts | AS-REP roast | T1558.004 | ✅ |
| 4.2 | Export hashes in hashcat format (`$krb5asrep$23$...`) | Hash export | — | ✅ |
| 4.3 | Optional cracking integration (hashcat/john/wordlist) | Hash cracking | T1110.002 | ✅ |
| 4.4 | If successful crack → add to `credentials.json` | Credential capture | T1078 | ✅ |
| 4.5 | Command: `asreproast [user ...]` | Direct CLI | — | ✅ |

**Depends on:** Phases 2, 3  
**Enables:** Phase 6 (auth), Phase 8  
**Done Criteria:** AS-REP hash exported; if wordlist provided, credentials recovered automatically.

---

### Phase 5 — Kerberoasting

> Second offline credential technique; complements AS-REP.

| ID | Task | Equivalent ADScan Technique | MITRE | Status |
|---|---|---|---|---|
| 5.1 | Request TGS for accounts with SPN | Kerberoast | T1558.003 | ✅ |
| 5.2 | Export hashes (`$krb5tgs$23$...`) | Hash export | — | ✅ |
| 5.3 | Optional cracking with wordlist | Hash cracking | T1110.002 | ✅ |
| 5.4 | Credential recovered → `credentials.json` | Credential capture | T1078 | ✅ |
| 5.5 | Command: `kerberoast [user ...]` | Direct CLI | — | ✅ |

**Depends on:** Phases 2, 3 (4 optional if credentials needed for preauth)  
**Enables:** Phase 6, 8  
**Done Criteria:** TGS hash exported for ≥1 account with SPN.

---

### Phase 6 — Password Spraying

> First online attack; needs users + lockout policy.

| ID | Task | Equivalent ADScan Technique | MITRE | Status |
|---|---|---|---|---|
| 6.1 | Fetch domain password policy (lockoutThreshold, lockoutDuration) via LDAP | Policy enum | T1110.003 | ✅ |
| 6.2 | Fetch `badPwdCount` per user (eligibility) | Lockout-aware | T1110.003 | ✅ |
| 6.3 | Spray engine: 1 password × N users (NetExec/kerbrute) | Password spray | T1110.003 | ✅ |
| 6.4 | Variation spray (Season+Year!, Company123, etc.) | Variation spray | T1110.003 | ✅ |
| 6.5 | History `spray_history.json` (do not repeat passwords) | Spray tracking | — | ✅ |
| 6.6 | Valid credentials → `credentials.json` | Credential capture | T1078 | ✅ |
| 6.7 | Command: `spray <password>` with confirmation | Direct CLI | — | ✅ |

**Depends on:** Phase 2  
**Enables:** Phase 7, 8  
**Done Criteria:** Spray of 1 password against a list of users without triggering lockout, capturing valid credentials if any.

---

### Phase 7 — Verification and credential management

> Bridge between obtained credentials and authenticated enumeration.

| ID | Task | Equivalent ADScan Technique | MITRE | Status |
|---|---|---|---|---|
| 7.1 | Verify credential: LDAP bind (user+pass) | Auth verify | T1078 | ✅ |
| 7.2 | Verify credential: SMB auth (user+pass / hash) | Auth verify | T1078 | ✅ |
| 7.3 | Verify credential: Kerberos TGT (user+pass / hash) | Auth verify | T1078 | ✅ |
| 7.4 | Command: `creds add <user> <secret>`, `creds list`, `creds verify` | Credential Mgmt | — | ✅ |
| 7.5 | Command: `start_auth` — starts authenticated flow with workspace credentials | Auth workflow | — | ✅ |
| 7.6 | Mark users as `owned` in the graph | Compromise tracking | — | ✅ |

**Depends on:** Phases 4, 5, or 6 (at least one credential)  
**Enables:** Phase 8+  
**Done Criteria:** Add credential manually, verify it, and mark user as compromised.

---

### Phase 8 — Authenticated enumeration (LDAP + SMB)

> With credentials, the landscape changes completely.

| ID | Task | Equivalent ADScan Technique | MITRE | Status |
|---|---|---|---|---|
| 8.1 | Authenticated LDAP: users, groups, computers, GPOs, OUs | LDAP enum | T1087.002 | ✅ |
| 8.2 | LDAP: delegations (unconstrained, constrained, RBCD) | Delegation enum | T1558 | ✅ |
| 8.3 | LDAP: ACLs and ACEs on high-value objects | ACL enum | T1098 | ✅ |
| 8.4 | SMB: active sessions, shares, permissions | SMB enum | T1021.002 | ✅ |
| 8.5 | SMB: GPP cpassword in SYSVOL | GPP passwords | T1552.006 | ✅ |
| 8.6 | Trust enumeration (external domains) | Trust spidering | T1482 | ✅ |
| 8.7 | ADCS: detect CA + enumerate certificate templates | ADCS discovery | T1649 | ✅ |
| 8.8 | Posture: LAPS, SMB signing, NTLMv1, LDAP signing, DA sessions | Misconfig checks | various | ✅ |
| 8.9 | Export BloodHound CE compatible JSON | BH collection | — | ✅ |

**Depends on:** Phase 7  
**Enables:** Phases 9–16  
**Done Criteria:** `start_auth` produces full inventory + `graph.json` + BloodHound export.

---

### Phase 9 — Attack graph and paths

> The ADScan differentiator: from raw data to exploitable paths.

| ID | Task | Equivalent ADScan Technique | MITRE | Status |
|---|---|---|---|---|
| 9.1 | Graph model: nodes (user, group, computer, domain) + edges (ACL, memberOf, AdminTo, etc.) | Attack graph | — | ✅ |
| 9.2 | Relations catalog with metadata (MITRE, severity, support) | Attack step catalog | — | ✅ |
| 9.3 | Algorithm: paths from `owned` → Domain Admins (BFS/DFS with depth) | Path computation | — | ✅ |
| 9.4 | Command: `paths` — list paths ordered by length/impact | Path listing | — | ✅ |
| 9.5 | Command: `paths show <id>` — step-by-step detail with narrative | Path detail | — | ✅ |
| 9.6 | Quick wins: User=Password, BlankPassword, GPP, creds in shares | Quick credential wins | T1078 | ✅ |

**Depends on:** Phase 8  
**Enables:** Phases 10–16  
**Done Criteria:** At least 1 path calculated from owned user to high-value group.

---

### Phase 10 — ACL abuse

| ID | Task | Technique | MITRE | Status |
|---|---|---|---|---|
| 10.1 | GenericAll → modify attributes / reset password | ACL abuse | T1098 | ✅ |
| 10.2 | GenericWrite → Shadow Credentials / SPN | ACL abuse | T1098 | ✅ |
| 10.3 | WriteDACL → self-grant GenericAll | ACL abuse | T1098 | ✅ |
| 10.4 | WriteOwner → take ownership → GenericAll | ACL abuse | T1098 | ✅ |
| 10.5 | ForceChangePassword | ACL abuse | T1098 | ✅ |
| 10.6 | AddMember → join privileged group | ACL abuse | T1098 | ✅ |
| 10.7 | AddSelf → GenericAll via group | ACL abuse | T1098 | ✅ |
| 10.8 | ReadLAPSPassword / ReadGMSAPassword | ACL abuse | T1555 | ✅ |
| 10.9 | WriteSPN / SPNJack | SPNJack | T1558 | ✅ |
| 10.10 | DCSync (GetChanges / GetChangesAll) | DCSync | T1003.006 | ✅ |

**Depends on:** Phases 8, 9

---

### Phase 11 — Advanced Kerberos

| ID | Task | Technique | MITRE | Status |
|---|---|---|---|---|
| 11.1 | Timeroasting | Timeroast | T1558.003 | ✅ |
| 11.2 | Unconstrained delegation + coercion | Delegation abuse | T1558 | ✅ |
| 11.3 | Constrained delegation (AllowedToDelegate) | Delegation abuse | T1558 | ✅ |
| 11.4 | RBCD (AllowedToAct / AddAllowedToAct) | RBCD | T1134.001 | ✅ |
| 11.5 | Shadow Credentials (AddKeyCredentialLink) | Shadow Creds | T1098 | ✅ |
| 11.6 | Backup Operators escalation | BO abuse | T1098 | ✅ |

**Depends on:** Phases 8, 9

---

### Phase 12 — ADCS (current ESC catalog)

| ID | Task | Technique | MITRE | Status |
|---|---|---|---|---|
| 12.1 | Detection of vulnerable templates (current ESC catalog) | ADCS enum | T1649 | ✅ |
| 12.2 | ESC1 exploitation (editable SAN + EKU) | ESC1 | T1649 | ✅ |
| 12.3 | ESC8 exploitation (NTLM relay → web enrollment) | ESC8 | T1649 | ✅ |
| 12.4 | ESC2–ESC7, ESC9–ESC15 + Golden Certificate | ADCS ESC | T1649 | ✅ |
| 12.5 | GoldenCert | CA abuse | T1649 | ✅ |

**Depends on:** Phase 8

---

### Phase 13 — Coercion and relay

| ID | Task | Technique | MITRE | Status |
|---|---|---|---|---|
| 13.1 | PetitPotam (EFSR RPC) | Coercion | T1187 | ✅ |
| 13.2 | PrinterBug (MS-RPRN) | Coercion | T1187 | ✅ |
| 13.3 | DFSCoerce, MS-EVEN, ShadowCoerce | Coercion | T1187 | ✅ |
| 13.4 | NTLM relay → LDAP (RBCD / Shadow Creds) | Relay | T1557.001 | ✅ |
| 13.5 | NTLM relay → ADCS (ESC8/ESC11) | Relay | T1649 | ✅ |
| 13.6 | NTLMv1 relay → RBCD / Shadow Creds | Relay | T1557.001 | ✅ |

**Depends on:** Phases 8, 12

---

### Phase 14 — Local post-exploitation

| ID | Task | Technique | MITRE | Status |
|---|---|---|---|---|
| 14.1 | AdminTo → SMB/WinRM access | Lateral movement | T1021 | ✅ |
| 14.2 | SAM dump (registry) | Cred dump | T1003.002 | ✅ |
| 14.3 | LSA Secrets | Cred dump | T1003.004 | ✅ |
| 14.4 | LSASS dump | Cred dump | T1003.001 | ✅ |
| 14.5 | DCSync (DRSUAPI) | DCSync | T1003.006 | ✅ |
| 14.6 | DPAPI secrets | Cred dump | T1555 | ✅ |
| 14.7 | Credentials in filesystem / shares | Share loot | T1552.001 | ✅ |
| 14.8 | RDP saved creds | Cred access | T1555.004 | ✅ |

**Depends on:** Phases 9, 10

---

### Phase 15 — MSSQL and lateral movement

| ID | Task | Technique | MITRE | Status |
|---|---|---|---|---|
| 15.1 | SQL Access / SQL Admin detection | MSSQL enum | T1021 | ✅ |
| 15.2 | Impersonation (SeImpersonate) | MSSQL privesc | T1068 | ✅ |
| 15.3 | Linked server lateral movement | MSSQL lateral | T1021 | ✅ |
| 15.4 | Trustworthy database escalation | MSSQL privesc | T1068 | ✅ |
| 15.5 | xp_cmdshell execution | MSSQL exec | T1059 | ✅ |

**Depends on:** Phase 8

---

### Phase 16 — CVEs and exploits

| ID | Task | Technique | MITRE | Status |
|---|---|---|---|---|
| 16.1 | noPac (CVE-2021-42278/42287) — detection + confirmed exploit | noPac | T1068 | ✅ |
| 16.2 | ZeroLogon (CVE-2020-1472) — detection, exploit with explicit confirmation | ZeroLogon | T1210 | ✅ |
| 16.3 | PrintNightmare — detection | PrintNightmare | T1068 | ✅ |
| 16.4 | MS17-010 (EternalBlue) — detection | EternalBlue | T1210 | ✅ |
| 16.5 | CVE catalog on DCs and workstations | CVE enum | T1210 | ✅ |

**Depends on:** Phase 8

---

### Phase 17 — Reporting and export

| ID | Task | Equivalent ADScan Technique | Status |
|---|---|---|---|
| 17.1 | Export TXT/JSON of findings | Evidence export | ✅ |
| 17.2 | MITRE ATT&CK Navigator layer | mitre-navigator | ✅ |
| 17.3 | Technical report JSON machine-readable | technical_report.json | ✅ |
| 17.4 | Executive PDF (future, non-blocking) | PRO deliverable | ⬜ |

**Depends on:** All previous phases

---

## 5. Implementation Order (Executive Summary)

```
Phase 0  ─── Foundation (CLI, workspace, creds store)
   │
Phase 1  ─── DNS + LDAP anon + SMB null + service discovery
   │
Phase 2  ─── SAMR + LDAP users + RID cycling → users.json
   │
Phase 3  ─── Detect roastables (AS-REP + Kerberoast targets)
   │
   ├─ Phase 4 ─── AS-REP Roasting
   ├─ Phase 5 ─── Kerberoasting
   └─ Phase 6 ─── Password Spraying
         │
Phase 7  ─── Verify creds + start_auth
   │
Phase 8  ─── Authenticated enum + GPP + trusts + ADCS discovery
   │
Phase 9  ─── Attack graph + paths
   │
   ├─ Phase 10 ── ACL abuse
   ├─ Phase 11 ── Kerberos advanced
   ├─ Phase 12 ── ADCS ESC
   ├─ Phase 13 ── Coercion + relay
   ├─ Phase 14 ── Post-exploit local
   ├─ Phase 15 ── MSSQL
   └─ Phase 16 ── CVEs
         │
Phase 17 ─── Reporting
```

**We start with Phase 0, then Phase 1, and advance sequentially.**  
Do not skip phases: each validates the previous one with tests and, if possible, an AD lab (HTB Forest is the benchmark for ADScan).

---

## 6. Immediate Checklist (Next 2 Weeks)

- [x] **0.1** Create `pyproject.toml` and package structure
- [x] **0.2** CLI `admapper start` with interactive shell
- [x] **0.3** Workspaces with JSON persistence
- [x] **0.4** Output with `rich` (banners, tables, confirmations)
- [x] **1.1** DNS SRV discovery module
- [x] **1.3** Anonymous LDAP probe
- [x] **1.4** SMB null session probe
- [x] **1.7** Integrated `start_unauth` command
- [ ] **2.1** SAMR user enumeration
- [ ] **2.4** Merge → `users.json`
- [ ] **3.1** Detect AS-REP roastables
- [ ] **4.1** Functional AS-REP Roasting
- [ ] Unit tests for each module with mocks

---

## 7. Quality Criteria (Each Technique)

Every implemented technique must meet:

1. **Isolated module** in its package (`recon/`, `creds/`, etc.).
2. **Unit tests** with mocks (without real AD mandatory).
3. **JSON artifact** in workspace (traceability).
4. **Entry in `findings.json`** with severity + MITRE ID.
5. **Direct CLI command** in addition to the automatic workflow.
6. **Confirmation** if the action is noisy (spray, exploit, dump).
7. **Inline documentation** — docstring with prerequisites and expected output.

---

## 8. WHAT ADScan DOES NOT DO (Future Backlog — After Parity)

These capabilities are left out of the MVP but documented to keep track.

### 8.1 Techniques that ADScan detects but does not auto-exploit

| Technique | State in ADScan | Our Opportunity |
|---|---|---|
| PetitPotam / PrinterBug / DFSCoerce | Detects, no auto-exploit | Auto-exploit with integrated relay from v1 |
| Direct Shadow Credentials | Partial | Full native implementation |
| GPP in attack graph | Unsupported in catalog | Integrate as executable edge |
| AddKeyCredentialLink | Unsupported | First class in Phase 11 |
| SID History / Golden Ticket | Not covered | Future phase |
| Silver Ticket | Not covered | Future phase |
| Pass-the-Ticket | Context only | Future phase |
| GPO abuse (Scheduled Tasks) | Not covered | Future phase |
| AdminSDHolder abuse | Not covered | Future phase |
| DSRM credential sync | Not covered | Future phase |
| Trust key abuse (inter-domain) | Partial (trust enum) | Cross-domain exploitation |
| Child → Enterprise DA | Partial | Full chain |

### 8.2 Outside the AD on-prem scope of ADScan

| Area | Description | Future Priority |
|---|---|---|
| **Azure AD / Entra ID** | ROADToken, PRT, CA policies, Graph API | High |
| **ADFS** | Golden SAML, token abuse | High |
| **Azure AD Connect** | MSOL password sync abuse | Medium |
| **Certificate-based auth (Smart Card)** | Advanced PKINIT abuse | Medium |
| **AD CS in cloud (Intune PKI)** | ESC adapted to cloud | Low |
| **Defender / EDR evasion** | OPSEC, timing, noise budget | Medium |
| **Continuous monitoring (CTEM)** | ADScan Enterprise | Low (separate product) |

### 8.3 Architectural improvements over ADScan

| Improvement | Why |
|---|---|
| **No mandatory Docker** | ADScan requires Docker; we support direct pip install |
| **Permissive License** | ADScan is BSL 1.1; we are Apache 2.0/MIT |
| **Modular, Testable Code** | ADScan is a monolith with a huge `adscan_internal` |
| **Programmatic API** | Python SDK for CI/CD (`admapper ci`) without REPL |
| **Plugins** | Third parties add techniques without fork |
| **OPSEC profiles** | Stealth / Normal / Lab presets |
| **Multi-tenant workspaces** | Multiple domains in one engagement |
| **Differential scans** | Only rescan what changed (delta) |

### 8.4 Validation Labs

| Lab | What it validates | Phases |
|---|---|---|
| HTB Forest | AS-REP → SMB null → DCSync chain | 1–4, 8, 10, 14 |
| HTB Active | GPP → Kerberoast → ACL | 5, 8, 10 |
| HTB Cicada | ADCS ESC + trust | 8, 12, 13 |
| GOAD (Game of Active Directory) | Full chain | All |

---

## 9. Reference: 64 Executable Techniques of ADScan

For parity, the final ADMapper catalog must cover at least these relationships from ADScan's `attack_step_catalog`:

<details>
<summary>Full list (click to expand)</summary>

**Credentials / roast / spray:**
`asreproasting`, `kerberoasting`, `timeroasting`, `passwordspray`, `useraspass`, `blankpassword`, `computerpre2k`

**ACL / LDAP:**
`genericall`, `genericwrite`, `owns`, `writedacl`, `writeowner`, `forcechangepassword`, `addself`, `addmember`, `readlapspassword`, `readgmsapassword`, `writeaccountrestrictions`, `writespn`, `spnjack`, `writelogonscript`, `dcsync`

**Delegation / Kerberos:**
`allowedtodelegate`, `hasshadowcredentials`, `ntlmv1relayrbcd`, `ntlmv1relayshadowcreds`

**ADCS:**
`adcsesc1`–`adcsesc15`, `coerceandrelayntlmtoadcs`, `goldencert`

**Lateral / access:**
`adminto`, `hassession`, `guestsession`, `canrdp`, `canpsremote`, `sqlaccess`, `sqladmin`

**MSSQL:**
`mssql_seimpersonate_escalation`, `mssql_token_theft_escalation`, `mssql_linked_server_lateral`, `mssql_impersonate_login`, `mssql_trustworthy_db_escalation`, `mssql_ntlmv2_theft`

**Post-exploit:**
`dumplsa`, `dumplsass`, `dumpdpapi`

**RODC / advanced:**
`backupoperatorescalation`, `preparerodccredentialcaching`, `extractrodckrbtgtsecret`, `forgerodcgoldenticket`, `kerberoskeylist`

**Shares:**
`readshare`, `writeshare`, `fullcontrolshare`

</details>

---

## 10. Planned CLI Commands

| Command | Phase | Description |
|---|---|---|
| `admapper start` | 0 | Opens interactive shell |
| `set workspace <name>` | 0 | Selects/creates workspace |
| `set domain <fqdn>` | 0 | Defines target domain |
| `set hosts <cidr/ip>` | 1 | Defines target range |
| `start_unauth` | 1 | Recon without credentials |
| `enum users` | 2 | Enumerate users (SAMR/LDAP/RID) |
| `asreproast` | 4 | AS-REP roasting + optional cracking |
| `guide <technique>` | * | Manual exploitation (BloodHound style) |
| `start_auth` | 7 | Full authenticated flow |
| `enum users` | 2 | Enumerate users |
| `asreproast` | 4 | AS-REP roasting |
| `kerberoast` | 5 | Kerberoasting |
| `spray <password>` | 6 | Password spraying |
| `creds add/list/verify` | 7 | Credentials management |
| `paths` | 9 | List attack paths |
| `exploit <step>` | 10+ | Execute path step |
| `export json/txt` | 17 | Export findings |

---

## 11. Session Notes

> Space to note decisions made during development.

| Date | Decision |
|---|---|
| 2026-06-04 | Language: Python 3.11+. Project name: **ADMapper**. License: Apache 2.0. |
| 2026-06-04 | Renamed ADIR → **ADMapper** (CLI: `admapper`, config: `~/.admapper/`). |
| 2026-06-04 | Order: Phase 0 → 1 → 2 → 3 → 4/5/6 → 7 → 8+. No skips. |
| 2026-06-04 | Parity Benchmark: ADScan LITE v9.x, 64 executable techniques. |
| 2026-06-24 | Phase 3 completed: `roastable.py` — pre-ticket detection of AS-REP + Kerberoast + PASSWD_NOTREQD targets. |
| 2026-06-24 | Phase 8.8 completed: `posture.py` — LAPS, SMB signing, NTLMv1, LDAP signing, DA sessions checks. |
| 2026-06-24 | Backlog — `coerce/exploit.py`: auto-exploit ntlmrelayx + coercers (PetitPotam, PrinterBug, DFSCoerce). |
| 2026-06-24 | Backlog — `core/opsec.py`: OPSEC profiles STEALTH/NORMAL/LAB. CLI: `admapper opsec set <profile>`. Tests: `test_opsec.py`. |
| 2026-06-24 | Backlog — `exploit/tickets.py`: `inject_ticket()` + `pass_the_ticket()` — PTT cross-platform (KRB5CCNAME / Rubeus). |
| 2026-06-24 | Backlog — `exploit/persistence.py`: `exploit_dsrm_backdoor()` — dump DSRM hash + DsrmAdminLogonBehavior. |
| 2026-06-24 | Backlog — `exploit/trusts.py`: `exploit_sid_history_nopac()` — SID History via CVE-2021-42278/42287 (noPac). |
| 2026-06-25 | PingCastle Posture Audits: Stale Systems, GPO Abuse, Stale AdminCount, and ESC8 HTTP web enrollment. |
| 2026-06-25 | CLI Visual Style System (output.py), `--no-color` option, privilege-free LDAP anonymous DC clock sync, and robust subprocess worker error wrapping. |

---

*This document is the source of truth for the project. Update upon completion of each phase.*
