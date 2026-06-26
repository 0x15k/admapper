# ADMapper

**All-in-one Active Directory pentesting toolkit.** Enumerate, attack, and own AD environments from a single CLI. Built for CTFs, cert labs, and real engagements.

> Python 3.11+ | macOS, Linux, Windows | No GUI required

## Features

- **Full AD enumeration** — users, groups, computers, GPOs, trusts, ACLs, SPNs, LAPS, delegations
- **Kerberos attacks** — AS-REP roasting, Kerberoasting, delegation abuse, Golden/Silver/Diamond/Sapphire tickets, PTT
- **AD CS exploitation** — ESC1-ESC14 detection and exploitation (certipy integration)
- **Credential attacks** — password spraying, DCSync, LAPS dump, shadow credentials, GPP passwords
- **Lateral movement** — WMI, PSExec, SMB, DCOM, AT exec, NTLM relay, coercion (PetitPotam, PrinterBug, DFSCoerce)
- **Privilege escalation** — RBCD, GPO abuse, trust exploitation, noPac (CVE-2021-42278/42287), SID History
- **Persistence** — AdminSDHolder, DSRM backdoor, certificate persistence, DCShadow
- **Security posture & Auditing (PingCastle style)** — SMB signing, LAPS coverage, NTLMv1, LDAP signing, DA session detection, Stale Systems (pwdLastSet / lastLogonTimestamp > 45 days), Writable GPOs / GPO Abuse, Stale AdminCount (Shadow Admins) detection, and ESC8 unencrypted web enrollment checks.
- **OPSEC profiles** — `stealth / normal / lab` — controls delays, confirmations, and feature gates
- **Automated pipeline** — `admapper run` chains recon + attack + escalation in one command
- **Guided exploitation** — each finding includes step-by-step exploitation guides (BloodHound-style)
- **Cert-ready** — works offline, exports to JSON/Navigator/HTML
- **Interactive Web Dashboard** — vis.js topology graph, auto-pivoting on node/identity selection, compromise tracking (🔑 password, #️⃣ NTLM hash, 💨 spray, 🎫 roast, etc.)

## Quick Start

```bash
# Install (macOS / Linux / Kali)
git clone https://github.com/0x15k/admapper.git && cd admapper
./scripts/install.sh

# Or one-liner:
curl -sSL https://raw.githubusercontent.com/0x15k/admapper/main/scripts/install.sh | bash

# Windows (PowerShell)
.\scripts\install.ps1
```

After install, `admapper` is available globally (via pipx):

```bash
# Full automated engagement — just IP + creds
admapper run -H <DC_IP> -u <user> -p '<pass>'
# Or via the short alias 'r':
admapper r -H <DC_IP> -u <user> -p '<pass>'

# Check installation health
admapper doctor
```

## Usage

### Automated Mode (recommended)

```bash
# Full pipeline: recon → attack → escalation
admapper run -H <DC_IP> -u <user> -p '<pass>'
# Or using the short alias 'r':
admapper r -H <DC_IP> -u <user> -p '<pass>'

# Specify domain explicitly (optional — auto-detected)
admapper r -H <DC_IP> -u <user> -p '<pass>' -d <DOMAIN>
```

### Playbook & Escalation Analysis

ADMapper supports built-in playbook and escalation sub-typers with clean commands, aliases, and automated scriptability:

- **Post-Exploitation Playbook** (`admapper postex` or alias `admapper px`):
  - View post-exploitation opportunities: `admapper px -w <workspace>` (or resolve workspace via `-H <ip>` / `-d <domain>`)
  - Remote WinRM scan for task hijack: `admapper px scan -H <WinRM_IP>`
  - View details of an opportunity: `admapper px show <op_id>`
  - Automatically deploy task hijack payload: `admapper px run --op <op_id>`
  
- **Escalation Path Analysis** (`admapper escalate` or alias `admapper esc`):
  - View escalation status (next hop): `admapper esc` or `admapper esc show`
  - Mark an account as compromised: `admapper esc mark <user>`
  - Change the active pivot node: `admapper esc pivot <user>`

- **Scriptability (`--json` output)**:
  For automated scripting and tools integration, pass the `--json` option to the main or show commands under postex/escalate. This silences terminal logging and returns clean structured JSON to stdout:
  ```bash
  admapper px -w <workspace> --json
  admapper px show postex-001 --json
  admapper esc -w <workspace> --json
  admapper esc show --json
  ```

### Interactive Mode

```
admapper
(admapper)> set workspace lab
(admapper:lab)> set domain <DOMAIN>
(admapper:lab:<DOMAIN>)> set hosts <IP_RANGE>

(admapper:lab:<DOMAIN>)> creds add <user> <pass>
(admapper:lab:<DOMAIN>)> start_unauth         # DNS, null LDAP, AS-REP
(admapper:lab:<DOMAIN>)> enum users            # LDAP user enumeration + roastable detection
(admapper:lab:<DOMAIN>)> kerberoast            # Kerberoasting
(admapper:lab:<DOMAIN>)> asreproast            # AS-REP roast
(admapper:lab:<DOMAIN>)> spray '<PASSWORD>'   # password spray

(admapper:lab:<DOMAIN>)> start_auth            # authenticated enumeration + security posture
(admapper:lab:<DOMAIN>)> enum auth             # full LDAP dump
(admapper:lab:<DOMAIN>)> acls                  # dangerous ACLs
(admapper:lab:<DOMAIN>)> paths                 # attack paths to DA
(admapper:lab:<DOMAIN>)> adcs                  # AD CS vulnerabilities
(admapper:lab:<DOMAIN>)> coerce                # NTLM coercion playbook
(admapper:lab:<DOMAIN>)> postex                # post-exploitation
(admapper:lab:<DOMAIN>)> export                # export all findings
```

### OPSEC Profiles

Control the noise level of every operation:

```bash
admapper opsec set stealth   # delays 3-10s, no spray, no coerce, confirms required
admapper opsec set normal    # balanced defaults
admapper opsec set lab       # no delays, no confirmations (lab/CTF use)
admapper opsec               # show current profile
```

| Profile | Delay | Spray | Coerce | Confirmations |
|---------|-------|-------|--------|---------------|
| `stealth` | 3–10s | ❌ | ❌ | always |
| `normal` | 0–0.5s | ✅ | ✅ | always |
| `lab` | none | ✅ | ✅ | never |

### Operational Methodology

ADMapper follows a dependency-driven pipeline so every step has context before moving on:

1. **Discovery** — `set hosts` → `start_unauth`
2. **Inventory** — `enum users` → roastable targets surfaced automatically
3. **Credential validation** — `creds add` → `creds verify`
4. **Auth collection** — `start_auth` → `enum auth` → `acls` → `adcs` → `coerce` → `mssql`
   - Security posture checked automatically: SMB signing, LAPS, NTLMv1, LDAP signing, DA sessions, stale systems, GPO abuse, shadow admins, and ESC8 unencrypted web enrollment CA checks.
5. **Attack execution** — `asreproast`, `kerberoast`, `spray`, `exploit`
6. **Pivoting / post-exploitation** — `pivot`, `winrm`, `postex`
7. **Synthesis** — `paths`, `brief`, `export`

### Workspace Artifacts

Each engagement stores its data in `workspaces/<name>/`:

| File | Contents |
|------|----------|
| `users.json` | All domain users with UAC flags, SPNs, roast flags |
| `roastable_targets.json` | Pre-attack AS-REP + Kerberoast + PASSWD_NOTREQD targets |
| `credentials.json` | Valid credentials and cracked hashes |
| `auth_inventory.json` | Full LDAP dump (users, groups, computers, GPOs, delegations) |
| `graph.json` | Attack graph nodes + edges |
| `findings.json` | Prioritised findings with MITRE mappings |
| `security_posture.json` | SMB signing / LAPS / NTLMv1 / LDAP signing / DA sessions / stale systems |
| `acl_findings.json` | Dangerous ACE findings (GenericAll, WriteDacl, etc.) |
| `adcs_findings.json` | ESC vulnerabilities |
| `kerberos_ops.json` | Delegation + shadow creds + timeroast opportunities |
| `coerce_ops.json` | NTLM coercion + relay playbook |
| `paths.json` | Attack paths to Domain Admin |
| `bloodhound/` | BloodHound CE-compatible JSON export |
| `loot/` | Captured hashes, DSRM hash, relay logs |

### Web UI parity

The web dashboard is a frontend for the CLI engine. Each GUI control maps to the same CLI command:

| GUI | CLI |
|---|---|
| Scan | `set hosts` + `start_unauth` |
| Authenticate | `creds add` + `creds verify` + `start_auth` |
| Enum Users | `enum users` |
| AS-REP Roast | `asreproast` |
| Kerberoast | `kerberoast` |
| Spray | `spray <password>` |
| ACLs | `acls` |
| ADCS | `adcs` |
| Coerce | `coerce` |
| Exploit | `exploit` |
| Pivot | `pivot <user>` |
| WinRM | `winrm <account>` |
| Brief | `brief` |

If a GUI action does not map to an existing CLI command, it should not exist as a separate implementation.

### Web UI Features

The dashboard includes advanced usability features to streamline engagements:
- **Auto-Pivoting**: Click any compromised user node or sidebar chip to instantly change the active pivot context on the backend.
- **Compromise Tracking**: Automatically identifies how accounts were pwned (Offline cracking, Password Spraying, ACL Exploitation, etc.) and tags them with visual status badges (🔑, #️⃣, 💨, 🎫, ⚡).
- **Structured Workspace Notes**: Groups engagement clues, validated credentials, lateral movement hashes, and required next steps into clean, color-coded status containers.

## Installation Details

### Requirements

- **Python 3.11+**
- **pipx** (installed automatically by the installer)

### Dependency Tiers

| Tier | What's included | Install |
|------|----------------|---------| 
| **core** | LDAP, DNS, CLI (no Impacket) | `pip install .` |
| **recon** | + Impacket (SMB, Kerberos, SAMR) | `pip install ".[recon]"` |
| **full** | + WinRM, GSSAPI, Kerberos libs | `pip install ".[full]"` (default) |
| **dev** | + pytest, ruff, bandit | `pip install ".[dev]"` |

### Platform Support

| OS | Status | Notes |
|----|--------|-------|
| **macOS** | Supported | Homebrew + pipx; primary dev platform |
| **Linux** | Supported | Kali/Parrot/Debian — auto-handles PEP 668 |
| **Windows** | Supported | PowerShell + pipx or venv |

### Companion Tools (install separately via pipx)

```bash
pipx install certipy-ad       # AD CS exploitation (ESC1-14)
pipx install pywhisker        # Shadow Credentials
pipx install netexec          # nxc (SMB/WinRM/LDAP)

# macOS
brew install hashcat john-jumbo libfaketime

# Linux / Kali
sudo apt install -y hashcat john
```

> **Why separate?** certipy-ad and pywhisker have conflicting dependency trees
> with Impacket. Installing them in isolated pipx environments avoids version
> conflicts and keeps everything working.

## Make Targets

```bash
make help           # show all targets
make install        # pipx global install
make install-dev    # dev install with pytest/ruff
make test           # run tests
make lint           # ruff linter
make format         # auto-format code
make security       # bandit security scan
make clean          # remove build artifacts
make doctor         # check installation health
```

## Project Structure

```
admapper/
├── admapper/               # source code
│   ├── cli/                # CLI entry point (typer) + interactive shell
│   ├── core/               # session, workspace, OPSEC profiles, output
│   ├── models/             # data models (UserRecord, Credential, Finding…)
│   ├── enumeration/        # LDAP/SAMR/RID user enum + roastable detection
│   ├── auth/               # authenticated LDAP+SMB enum, security posture
│   ├── recon/              # unauthenticated recon (DNS, null LDAP, SMB)
│   ├── acl/                # ACL/ACE enumeration and analysis
│   ├── adcs/               # AD CS detection (ESC1-14)
│   ├── kerberos/           # Kerberos attack surface analysis + timeroast
│   ├── coerce/             # coercion playbook + NTLM relay auto-exploit
│   ├── exploit/            # exploitation engine (tickets, RBCD, shadow creds,
│   │                       #   GPO abuse, LAPS, gMSA, DCSync, persistence…)
│   ├── creds/              # credential management + cracking + spraying
│   ├── escalate/           # privilege escalation analysis
│   ├── postex/             # post-exploitation (DLL hijack, scheduled tasks)
│   ├── analysis/           # attack path computation + user intel
│   ├── graph/              # web dashboard + attack graph
│   ├── report/             # export (JSON, Navigator, HTML)
│   ├── guides/             # manual exploitation guides per technique
│   ├── mssql/              # MSSQL enumeration and exploitation
│   ├── winrm/              # WinRM remote execution
│   ├── cves/               # CVE-specific checks (noPac, PrintNightmare…)
│   ├── chain/              # automated exploit chain engine
│   └── methodology/        # engagement methodology helpers
├── scripts/                # installers (sh, ps1)
├── tests/                  # test suite (319 tests)
├── docs/                   # documentation
└── workspaces/             # engagement data (gitignored)
```

## Documentation

- **[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)** — platform installation instructions, compatibility tiers, and dependencies
- **[docs/PROJECT.md](docs/PROJECT.md)** — project blueprint, architecture, roadmaps, and phases (source of truth)

## License

Apache-2.0
