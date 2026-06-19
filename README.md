# ADMapper

**All-in-one Active Directory pentesting toolkit.** Enumerate, attack, and own AD environments from a single CLI. Built for OSCP, HTB, and real engagements.

> Python 3.11+ | macOS, Linux, Windows | No GUI required

## Features

- **Full AD enumeration** — users, groups, computers, GPOs, trusts, ACLs, SPNs, LAPS
- **Kerberos attacks** — AS-REP roasting, Kerberoasting, delegation abuse, Golden/Silver tickets
- **AD CS exploitation** — ESC1-ESC14 detection and exploitation
- **Credential attacks** — password spraying, DCSync, LAPS dump, shadow credentials
- **Lateral movement** — WMI, PSExec, SMB, DCOM, AT exec, NTLM relay
- **Privilege escalation** — RBCD, GPO abuse, trust exploitation, persistence
- **Automated pipeline** — `admapper run` chains recon + attack + escalation in one command
- **Guided exploitation** — each finding includes step-by-step exploitation guides
- **OSCP-ready** — works offline, exports to JSON/Navigator/HTML

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
admapper run -H 10.10.10.100 -u john -p 'Password1!'

# Check installation health
admapper doctor
```

## Usage

### Automated Mode (recommended)

```bash
# Full pipeline: recon → attack → escalation
admapper run -H <DC_IP> -u <user> -p '<pass>'

# Specify domain explicitly (optional — auto-detected)
admapper run -H 10.10.10.100 -u admin -p 'P@ss' -d corp.local
```

### Interactive Mode

```
admapper
(admapper)> set workspace lab
(admapper:lab)> set domain corp.local
(admapper:lab:corp.local)> set hosts 10.10.10.100

(admapper:lab:corp.local)> creds add john Password1!
(admapper:lab:corp.local)> start_unauth         # DNS, null LDAP, AS-REP
(admapper:lab:corp.local)> enum users            # LDAP user enumeration
(admapper:lab:corp.local)> kerberoast            # Kerberoasting
(admapper:lab:corp.local)> asreproast            # AS-REP roast
(admapper:lab:corp.local)> spray 'Winter2026!'   # password spray

(admapper:lab:corp.local)> start_auth            # authenticated enumeration
(admapper:lab:corp.local)> enum auth             # full LDAP dump
(admapper:lab:corp.local)> acls                  # dangerous ACLs
(admapper:lab:corp.local)> paths                 # attack paths to DA
(admapper:lab:corp.local)> adcs                  # AD CS vulnerabilities
(admapper:lab:corp.local)> coerce                # NTLM coercion checks
(admapper:lab:corp.local)> postex                # post-exploitation
(admapper:lab:corp.local)> export                # export all findings
```

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
├── admapper/           # source code
│   ├── cli/            # CLI entry point (typer)
│   ├── recon/          # DNS, LDAP, SMB enumeration
│   ├── analysis/       # attack path analysis
│   ├── adcs/           # AD CS detection (ESC1-14)
│   ├── exploit/        # exploitation engine
│   ├── escalate/       # privilege escalation
│   ├── graph/          # attack graph visualization
│   └── report/         # export (JSON, Navigator, HTML)
├── scripts/            # installers (sh, ps1)
├── tests/              # test suite
├── docs/               # documentation
└── workspaces/         # engagement data (gitignored)
```

## Documentation

- **[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)** — platform-specific details
- **[docs/PLATFORMS.md](docs/PLATFORMS.md)** — step-by-step installation
- **[docs/DEPENDENCIES.md](docs/DEPENDENCIES.md)** — dependency breakdown
- **[docs/PROJECT.md](docs/PROJECT.md)** — project roadmap and phases

## License

Apache-2.0
