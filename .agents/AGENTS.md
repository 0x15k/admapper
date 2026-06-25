# ADMapper Active Directory Pentesting Tool - Agent Context

This document provides project-scoped rules, architecture guidelines, and logic flow overview of ADMapper. Future AI agents loading this workspace should read this context first before implementing changes.

## 1. Project Philosophy & Stack
- **Architecture**: Domain escalation, reconnaissance, credential collection, and post-exploitation reporting.
- **Language**: Python >= 3.11 (utilizing `dataclasses`, custom type hints, standard logging).
- **Testing**: `pytest` running inside local virtual environment (`.venv/bin/pytest`). Global `pytest` must be avoided due to system interpreter incompatibilities.
- **Frontend / Dashboard**: Zero-framework vanilla HTML, CSS3 variables, and vanilla JS. Vis.js is used for graph rendering. Tailwind, React, or Vue must not be introduced.

## 2. Exploits Architecture (`admapper/exploit/`)
- All exploit techniques inherit from the abstract base class `BaseExploit` in [base.py](file:///Users/yamillabarreralopez/Projects/admapper/admapper/exploit/base.py):
  - `name`: Identifier string.
  - `description`: A short explanation.
  - `check_prerequisites(session) -> bool`: Pre-check for creds/targets.
  - `run(session, **kwargs) -> ExploitResult`: Unified execution routine.
- Unified Credential Model: Active credentials should be read from/saved to `session.credentials` via the `Credential` model ([credential.py](file:///Users/yamillabarreralopez/Projects/admapper/admapper/models/credential.py)).

## 3. Post-Exploitation Opportunities (`admapper/postex/`)
- Local shell techniques (`sam_dump`, `lsass_dump`, etc.) are mapped to target hosts where valid local admin access is confirmed (based on verified credentials or active ownership), instead of a generic `<local_shell>`.
- DCSync is marked as `ready`/`critical` only if the principal has explicit DRSUAPI rights (`GetChanges`/`GetChangesAll` in `acl_findings.json`) and no previous execution attempts failed (`ERROR_DS_DRA_BAD_DN`). Failed DCSync rounds automatically downgrade the opportunity severity to `info`.
- Relay-based techniques (like ESC8 and ESC11) specify `requires_external_listener: true` to alert the operator in the dashboard.

## 4. Operational Pipeline & Graph Filters
- Users/systems are color-coded in Vis.js by status: Compromised (green), Pivot (cyan), High Value/DC (red/orange).
- Graph views switch dynamically between `[All]`, `[High Value]`, `[Compromised]`, and `[Attack Path Only]`.
- The `krbtgt` account is explicitly excluded from standard Kerberoasting path listings as it cannot be roasted in standard ways.
- In `LAB` opsec mode, accounts flagged as `PASSWD_NOTREQD` (e.g. Guest) are automatically sprayed with a blank password during initial rounds.

## 5. CLI Ergonomics, Parameter Consistency & JSON Outputs
- **CLI Command Aliases**:
  - Hidden sub-typer aliases are registered for main sub-typers (`px` for `postex` and `esc` for `escalate`).
  - Hidden command aliases are registered for main commands (`r` for `run` and `g` for `graph`).
- **Workspace/Target Flag Consistency**:
  - Target host (`-H`/`--host`), domain (`-d`/`--domain`), and workspace (`-w`/`--workspace`) parameters are consistent across all subcommands.
  - Workspace lookup is handled dynamically by `_session_with_workspace(workspace, host, domain)` in `admapper/cli/main.py`.
- **Structured JSON Outputs**:
  - Main callbacks and `show` commands under `postex` and `escalate` support a `--json` output flag.
  - When `--json` is specified, the command invokes the underlying analyzer in `quiet` mode (suppressing console info/warning prints) and outputs the clean serialized JSON payload to `stdout`.
- **Dashboard API Consistency**:
  - Backend API JSON payload parsing endpoints (`/api/scan`, `/api/run`, `/api/pivot`, `/api/winrm`) support alternative parameter names matching standard CLI flags (`host`/`ip_dc`/`user`/`username`/`p`/`password`).
