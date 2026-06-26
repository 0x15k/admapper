# ADMapper — Compatibility, Dependencies, and Platforms

ADMapper is a **Python package** with a console script (`admapper`). It is installed via `pip` and runs on the local operating system's Python interpreter.

---

## 1. Requirements and Python Versions

- **Minimum version:** Python 3.11+
- **Tested versions:** Python 3.11 to 3.14
- **Distribution Entry Point:** `admapper` -> `admapper.cli.main:main`

---

## 2. Dependency Tiers

To facilitate flexibility in different environments, ADMapper dependencies are split into `pip` extras. This allows its use from basic LDAP scans in restrictive environments to a complete toolkit with Kerberos/SMB exploit scripts.

| Extra | Pip Command | Includes | Multi-platform? |
|---|---|---|---|
| *(none)* | `pip install admapper` | **CORE**: typer, rich, prompt-toolkit, ldap3, dnspython | ✅ Yes — pure Python code |
| `recon` | `pip install "admapper[recon]"` | **CORE** + **RECON** (impacket) | ✅ Yes* — pip wheel; requires MSVC runtime on Windows occasionally |
| `full` | `pip install "admapper[full]"` | Same as `recon` (default recommended tier) | ✅ Yes |
| `dev` | `pip install -e ".[dev]"` | + ruff, bandit | ✅ Yes |

> [!NOTE]
> Dependencies in `pyproject.toml` use compatible semver ranges (`>=X,<Y`). Impacket is pinned to `<0.13` to ensure compatibility with its internal API.

---

## 3. Compatibility Matrix by Command

The availability of ADMapper features on each platform depends on the minimum tier required by the command:

| Command | Minimum Tier | Runtime | macOS | Linux | Windows |
|---|---|---|---|---|---|
| `admapper start` | CORE | Python | ✅ | ✅ | ✅ |
| `start_unauth` | CORE | dnspython + socket | ✅ | ✅ | ✅ |
| `enum users` (LDAP) | CORE | ldap3 | ✅ | ✅ | ✅ |
| `enum users` (SAMR/RID) | RECON | impacket | ✅ | ✅ | ✅* |
| `asreproast` / `kerberoast` | RECON | impacket subprocess | ✅ | ✅ | ✅* |
| automatic cracking | EXTERNAL | hashcat/john | ✅† | ✅† | ✅† |
| `spray` (default) | CORE | ldap3 bind | ✅ | ✅ | ✅ |
| `spray --method kerbrute` | EXTERNAL | kerbrute binary | ✅† | ✅† | ✅† |
| `creds verify` (LDAP) | CORE | ldap3 | ✅ | ✅ | ✅ |
| `creds verify` (SMB/KRB) | RECON | impacket | ✅ | ✅ | ✅* |
| `start_auth` | CORE | ldap3 + JSON | ✅ | ✅ | ✅ |

† = Requires external binary installed in the PATH.  
\* = With active venv and `[recon]` dependencies installed correctly.

---

## 4. Companion Tools

Some of the advanced exploitation tools are installed in isolation via `pipx` to avoid direct dependency conflicts with Impacket:

```bash
pipx install certipy-ad       # For AD CS exploitation (ESC1-ESC14)
pipx install pywhisker        # For Shadow Credentials
pipx install netexec          # nxc (For WinRM/SMB remote execution and verification)
```

---

## 5. Common Paths and Environment

ADMapper organizes its configuration, wordlists, and engagement data consistently according to the operating system:

| Resource | macOS / Linux | Windows |
|---|---|---|
| Config Directory | `~/.admapper/` | `%USERPROFILE%\.admapper\` |
| Default Wordlists | `~/.admapper/wordlists/rockyou.txt` | `%USERPROFILE%\.admapper\wordlists\rockyou.txt` |
| Workspaces (Data) | `~/.admapper/workspaces/` | `%USERPROFILE%\.admapper\workspaces\` |
| REPL History | `~/.admapper/history` | `%USERPROFILE%\.admapper\history` |

*Note: You can override the workspace directory with the global CLI flag `admapper -O <path>`, by setting `set workspaces <path>` in the interactive console, or using the environment variable `$ADMAPPER_WORKSPACES`.*

---

## 6. Installation by Platform

### macOS
Requires Xcode Command Line Tools (`xcode-select --install`).

- **Global Installation (Recommended via pipx)**:
  ```bash
  cd admapper
  ./scripts/install.sh
  ```
- **Development Installation (venv)**:
  ```bash
  ./scripts/install.sh --venv
  source .venv/bin/activate
  ```
- **Optional Network Tools (Homebrew)**:
  ```bash
  brew install hashcat john-jumbo rust python@3.13
  # Note: On Apple Silicon these are installed under /opt/homebrew/bin
  ```

### Windows
Requires Python 3.11+ (ensure "Add Python to PATH" is checked in the installer).

- **Virtual Environment Installation**:
  ```powershell
  cd admapper
  python -m venv .venv
  .\.venv\Scripts\activate
  pip install -e ".[dev,recon]"
  ```
- **Windows Notes**:
  - Activate the virtual environment (`.venv`) before running `admapper start` to load Impacket and NetExec from `.venv\Scripts\`.
  - If you encounter SMB issues with local scripts, you can optionally install `pywin32`.

### Linux (Kali / Debian / Parrot)
- **Isolated Environment Installation (venv)**:
  ```bash
  sudo apt install python3-venv seclists hashcat john
  cd admapper
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -e ".[dev,recon]"
  ```

---

## 7. Executable Search and Resolution

When invoking auxiliary binaries (such as `nxc`, `certipy`, `faketime`, etc.), ADMapper performs automatic searches in the following order of priority:
1. System `PATH`.
2. Active Python/venv `bin` or `Scripts` folder.
3. Default operating system installation directories (for example, `/opt/homebrew/bin` on Apple Silicon macOS).

To validate whether tools are correctly mapped, run the interactive diagnostic command:
```
(admapper)> platform
```

---

## 8. Portability Principles

### What IS portable (Core Python):
1. Paths resolved via `pathlib.Path` and `Path.home()` (resolves to `%USERPROFILE%` or `/home/` as appropriate).
2. Automatic discovery of system dictionaries (`/usr/share/wordlists` on Kali vs local fallback paths).
3. File-based structured JSON persistence to avoid relational database dependencies.

### What is NOT portable (External Binaries):
1. Hardware acceleration for `hashcat` or `john`.
2. Network routing or VPN adapters (the DC must be reachable via standard network routing).
3. Corporate Docker environments (ADMapper is designed to run natively without requiring containerization).
