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
