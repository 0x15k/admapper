---

# ADMapper — Architecture Skill

## What ADMapper Is
A professional Active Directory pentesting and post-exploitation tool written in Python.
Covers the full engagement lifecycle: recon, enumeration, exploitation, post-exploitation,
reporting, and dashboard visualization for authorized red team engagements.

## Full Module Map
admapper/

├── cli/               # CLI entry points and command routing — no business logic

│   └── commands/      # One file per command group (recon, postex, escalate, etc.)

├── acl/               # ACL enumeration, parsing, analysis, and rights evaluation

├── adcs/              # AD Certificate Services — ESC detection, certipy integration

├── auth/              # Authentication: LDAP, SMB, Kerberos, BloodHound export

├── chain/             # Attack chain analysis and reanalysis

├── coerce/            # Coercion attacks (PetitPotam, etc.)

├── creds/             # Credential management, spraying, password policy

├── cves/              # CVE detection and exploitation modules

├── dashboard/         # Web dashboard — ops state, HTML, WinRM proxy

├── engage/            # Automated engagement orchestration

├── enum/              # LDAP/SAMR enumeration, RID cycling, roastable accounts

├── escalate/          # Privilege escalation path analysis

├── exploit/           # Exploitation: ACL abuse, DCSync, RBCD, shadow creds, etc.

├── graph/             # Attack graph construction and path analysis

├── guides/            # Pentest methodology guides and SVG flows

├── intelligence/      # Engagement intel, attack readiness, password rules

├── kerberos/          # Kerberoast, AS-REP roast, timeroast, clock skew

├── methodology/       # Unified methodology framework

├── models/            # Dataclasses and shared types — no methods with side effects

├── mssql/             # MSSQL enumeration and analysis

├── postex/            # Post-exploitation core (see detail below)

├── posture/           # Security posture assessment

├── recon/             # DNS, port scan, SMB/LDAP probe, unauthenticated recon

├── report/            # Report generation: HTML, TXT, evidence, MITRE navigator

├── stores/            # In-memory stores: credentials, findings, graph, hosts, users

├── support/           # Output formatting, session, config, provenance, workspace

├── winrm/             # WinRM client, transport, upload, shell

└── wsus/              # WSUS attack surface analysis

## Postex Module Detail
admapper/postex/

├── remote_scan.py     # WinRM remote execution and log discovery — network I/O only

├── hijack_intel.py    # Pattern matching and intel extraction — no network calls

├── task_hijack.py     # Finding construction and severity scoring

├── loot_intel.py      # Local loot directory analysis

├── deploy.py          # Payload packaging and upload

├── dllgen.py          # msfvenom DLL generation

├── runner.py          # Orchestration only — no logic

├── payload.py         # Payload model

├── pe_arch.py         # PE architecture detection

├── listener.py        # Reverse shell listener

├── creds.py           # WinRM credential resolution

├── catalog.py         # Postex technique catalog

├── templates.py       # Command template rendering

├── analyze.py         # Post-run analysis

└── render.py          # Output rendering

## Core Design Rules

### Separation of concerns
- remote_scan.py: network I/O and raw output only — no parsing logic
- hijack_intel.py: pattern matching and intel extraction only — no network calls
- task_hijack.py: finding construction only — receives parsed intel, emits findings
- deploy.py: payload packaging and upload only — receives paths, no discovery
- runner.py and cli/: orchestration only — never contain business logic
- models/: dataclasses only — no methods with side effects
- stores/: stateful in-memory stores — no business logic, no network calls
- dashboard/: presentation only — reads from stores and session, never writes findings

### Data flow (one direction only)
recon → enum → auth → stores

stores → graph → escalate → exploit

loot_intel → hijack_intel → task_hijack → deploy → runner

remote_scan → hijack_intel → task_hijack → deploy → runner
Modules downstream never import from modules upstream.

### Never hardcode environment-specific values
- No hardcoded log filenames — use pattern-based discovery
- No hardcoded service or task names — derive from loot or remote scan
- No hardcoded paths beyond Windows system defaults ($env:ProgramData, $env:windir)
- No hardcoded lab IPs, domains, usernames, or hashes anywhere in source

### Finding output contract
Every finding must include:
- task_name / technique identifier
- run_as_user or affected principal
- drop_path or target path
- payload references if applicable
- writable: bool — must be True to be actionable in postex
- severity: critical / high / medium / info
- evidence: list of strings explaining why this is a finding

### Severity scoring
| Severity | Criteria |
|----------|----------|
| critical | Confirmed write access + non-system account execution context |
| high     | Strong loot hints with drop_path OR confirmed writable |
| medium   | Pattern match found, write access not yet verified |
| info     | Candidate only — needs manual verification |

### CLI output style
Follow LinPEAS / NetExec / Nuclei conventions:
- [*] info / progress
- [+] success
- [-] failure
- [!] warning
- No emojis, no verbose prose, no repeated banners
- Every line must be actionable or skippable at a glance

### WinRM execution
- Always use WinRMClient from winrm/client.py — never subprocess or raw sockets
- Wrap every client.execute() in try/except WinRMError
- Shell type must be explicit: shell="powershell" or shell="cmd"
- Never mix PowerShell and cmd in the same execute() call

### Regex and pattern matching
- All patterns defined at module level as compiled constants (re.compile)
- Named with _RE suffix: _WIN_PATH_RE, _ZIP_NAME_RE, etc.
- No inline re.search() with raw strings in business logic
- Patterns must be environment-agnostic

### No hardcoded fallbacks that mask bugs
- If intel cannot be derived, return None — do not invent paths
- Default to r"C:\ProgramData" only as last resort, always log a warning
- Every None return must be handled explicitly by the caller

### Workspace structure
workspaces/<target-ip>/

├── loot/              # Files pulled from target (logs, SYSVOL, NETLOGON)

├── payloads/          # Generated DLLs and ZIPs

├── bloodhound/        # BloodHound JSON exports

├── *.json             # Per-module output files

└── *.html / *.txt     # Reports
Never write output files outside the workspace for the current session target.

## Skills Index
| Skill | Scope |
|-------|-------|
| admapper/skills/architecture.md | Global rules — read before touching any file |
| admapper/skills/dashboard.md | Dashboard HTTP/SSE layer — consumer only |
| admapper/skills/hijack_detection.md | postex/hijack_intel.py + remote_scan.py |
| admapper/skills/loot_analysis.md | postex/loot_intel.py (pending) |
| admapper/skills/output_format.md | CLI output formatting (pending) |

## CLI Engine — Command Execution (single source of truth)

All operator actions — REPL, `admapper run`, and the web dashboard — must route through
the same engine. There is no `admapper/core/` or `admapper/engine/` package; the engine is
the combination of layers below.

### Execution stack

```
Browser / REPL line
    → admapper/cli/commands/dispatch.py     # parse + route (no business logic)
    → admapper/cli/commands/{meta,recon,...}.handle  # thin command adapters
    → technique modules (recon/, enum/, exploit/, …)  # business logic + artifacts
    → admapper/support/session.py           # Session + workspace persistence
    → admapper/stores/                      # in-memory JSON-backed stores
```

**Rules:**
- `dispatch(session, line)` is the only command router. Dashboard ops call
  `dispatch(session, 'start_unauth')`, not a parallel code path.
- Technique logic lives in `recon/`, `enum/`, etc. — never in `dashboard/` or duplicated
  in `dashboard_server.py`.
- `Session.bootstrap()` + `session.select_workspace()` bind workspace state before any op.

### Recon / Discovery without credentials

| Layer | Module | Responsibility |
|-------|--------|----------------|
| Command | `cli/commands/recon.py` | `start_unauth` → `run_unauth_scan(session)` |
| Engine | `recon/unauth.py` | DNS, port scan, LDAP/SMB probes, writes `unauth_scan.json` |
| Probes | `recon/ldap_probe.py`, `recon/dns.py`, … | Network I/O only |
| Summary | `cli/scan.py` | `run_unauth_discovery(session)` + `print_scan_summary(session)` |
| Output | `support/output.py`, `support/verbosity.py` | Rich console; `quiet_*` / `is_compact()` for dashboard |

If Discovery without auth is broken or quiet, fix **`recon/unauth.py`** or
**`support/verbosity.py`** — not a dashboard-specific workaround.

### Output and streaming

```
technique code
    → support/output.py (print_info, print_success, …)
    → rich.console.Console  (global `console` in support/output.py)
```

**Interactive CLI:** stdout is the real terminal.

**Dashboard in-process ops** (`DashboardContext._run_workspace_script`):

```
enable_dashboard_mode()  → ADMAPPER_DASHBOARD_MODE=1
console.file = DashboardStream(ctx)   # dashboard/terminal_stream.py
exec(script with session bound)
    → dispatch / run_unauth_scan / print_scan_summary
    → console.print → DashboardStream.write
    → TerminalFilter.process (strip noise, dedupe)
    → ctx.emit → events queue
GET /api/events (SSE) → browser terminal
```

**External binaries** (`_run_subprocess`): stdout/stderr piped line-by-line through the
same `TerminalFilter` before `ctx.emit`. Use only when a real subprocess is required
(e.g. bloodhound-python).

**Rule:** If terminal streaming is broken, fix **`terminal_stream.py`**, **`terminal_filter.py`**, or
**`support/output.py`** — not by re-emitting duplicate lines from dashboard orchestration.

### Dashboard = consumer only

| Allowed in `dashboard/` | Forbidden in `dashboard/` |
|-------------------------|---------------------------|
| HTTP routes, SSE, `DashboardContext` orchestration | Reimplementing LDAP/DNS/port scan logic |
| `dispatch(session, …)` via `_run_workspace_script` | Parsing `unauth_scan.json` for a parallel summary format |
| `TerminalFilter` presentation | Duplicating `print_scan_summary` / recon milestones |
| `build_ops_payload()` UI state | Writing findings or mutating technique artifacts outside Session |

GUI actions map **1:1 to CLI commands** (`dispatch` or the same functions the CLI calls).
Post-run summaries call **`cli/scan.run_unauth_discovery`** and **`print_scan_summary`** — never dashboard-only helpers.

## Anti-patterns (never do these)
❌ Business logic in runner.py, cli/, or dashboard/
❌ Dashboard-specific recon or scan-summary logic — use `recon/unauth.py` + `cli/scan.py`
❌ Duplicate `[*] Running:` from server when the client already logs the op label
❌ Reimplementing `set hosts` in dashboard scripts when `_persist_target_ip` already ran
❌ Network calls in hijack_intel.py or task_hijack.py
❌ Hardcoded filenames, service names, or lab-specific strings
❌ CTF/lab platform names or box codenames in UI placeholders, hints, or docs (use `corp-internal`, `corp.local`, `192.168.x.x`)
❌ Returning a default finding when intel is None
❌ Importing downstream modules from upstream ones
❌ Regex patterns as inline strings inside functions
❌ execute() calls without explicit shell= parameter
❌ Writing files outside the active workspace directory
