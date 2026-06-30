# SKILL: postex & DLL Hijack Detection

Read this file completely before touching any module under `admapper/postex/` or `admapper/escalate/`.

---

## Module Map

```
admapper/postex/
├── analyze.py          # Phase 14 orchestrator — builds PostexOpportunity list
├── catalog.py          # PostexTechnique registry — source of truth for all metadata
├── task_hijack.py      # DLL hijack detection logic (TaskHijackAnalysis, findings)
├── hijack_intel.py     # Artifact/log parser → HijackIntel (paths, zip, dll, drop_path)
├── loot_intel.py       # Scans workspaces/<n>/loot/ for zip/dll/task references
├── templates.py        # Variable substitution for manual_commands
├── shell_client.py     # ReverseShellRepl — interactive shell over TCP listener
├── listener.py         # ReverseShellListener — TCP catch
├── remote_scan.py      # WinRM-based remote task scan → postex_scan.json
├── nxc_output.py       # Strip nxc/WinRM output prefix noise
└── pe_arch.py          # Infer target arch (x86/x64) from monitor log
```

---

## Core Data Flow

```
workspace artifacts
  auth_inventory.json   → computer targets, SMB shares
  acl_findings.json     → DCSync principal detection
  paths.json            → AdminTo path targets
  loot/                 → zip/dll/task refs (LootIntelResult)
  postex_scan.json      → remote WinRM scan output (optional)
          │
          ▼
    analyze.py::build_postex_opportunities()
          │
          ├─ _computer_targets()       → list[str] from inventory.computers (max 25)
          ├─ _owned_users()            → session.workspace.owned_users
          ├─ dcs                       → HostsStore → is_domain_controller hosts
          │
          ├─ Technique detection:
          │   14.1  adminto            → per computer (capped at 3 in prioritizer)
          │   14.2–8 local shell       → verified_admin_hosts only (NOT generic fallback)
          │   14.5  dcsync             → ACL findings with right=="dcsync" + exploit_log.json
          │   14.7  share_loot         → SMB shares from inventory
          │   14.9  dll_hijack         → task_hijack.py + hijack_intel.py + loot
          │
          ▼
    list[PostexOpportunity] → deduplicated → _prioritize_postex_ops()
          │
          ▼
    postex_ops.json   (written to workspace)
```

---

## Key Classes & Contracts

### `PostexOpportunity` (`admapper/models/postex_op.py`)
All fields come from `PostexTechnique` in `catalog.py` plus runtime context:
```python
technique: str          # key matching POSTEX_TECHNIQUES dict
title: str
severity: str           # critical | high | medium | info
mitre_id: str
summary: str
target_host: str | None
context: str | None     # owned user / cred context
detail: str
manual_commands: list[str]
id: str                 # assigned after build ("postex-001", ...)
dcsync_attempted: bool  # set only on dcsync ops
dcsync_failed: bool
```

### `PostexTechnique` (`catalog.py`)
**The only place to add/modify technique metadata.** Never hardcode titles, severity, MITRE IDs, or commands in `analyze.py` or `task_hijack.py` — always go through `postex_meta(key)`.

Current technique keys:
```
adminto | sam_dump | lsa_secrets | lsass_dump | dcsync | dpapi
share_loot | rdp_creds | scheduled_task_com_enum | dll_hijack_scheduled_task
```

### `TaskHijackAnalysis` (`task_hijack.py`)
```python
findings: list[TaskHijackFinding]   # actionable hijack opportunities
tasks: list[ScheduledTaskRecord]    # raw COM/schtasks parsed lines
monitor_log_excerpt: str            # first 2000 chars
acl_excerpt: str                    # first 1000 chars
hijack_intel: dict                  # HijackIntel fields as dict
```

### `HijackIntel` (`hijack_intel.py`)
```python
payload_zip: str         # e.g. "update.zip"
payload_dll: str         # e.g. "plugin.dll"
drop_path: str           # e.g. r"C:\ProgramData\vendor"
monitor_log_path: str | None
task_name_hint: str | None
com_task_filter: str | None
```

---

## DLL Hijack Detection Pipeline

Service log paths are **discovered** from loot, remote WinRM scan, or
`monitor_log_excerpt` / `hijack_intel.monitor_log_path` in `postex_scan.json` —
never assumed from a fixed basename. `postex run` polls the stored path or probes
common log names under the discovered `drop_path` (see `remote_scan._SERVICE_LOG_PATHS`).

```
loot/           → scan_loot_directory() → LootIntelResult
                    .zip_dll_refs       list[str]  raw lines with .zip/.dll
                    .dll_hijack_refs    list[str]
                    .task_hints         list[TaskHint]

postex_scan.json (optional, from remote WinRM scan)
    → analysis_from_scan_payload()     bypasses re-analysis if findings already present

analyze_task_hijack():
    1. _parse_com_task_lines(com_task_output)    → list[ScheduledTaskRecord]
    2. extract_hijack_intel(loot, monitor_log, com_task_output)
           → tries _intel_from_service_lines() on monitor_log first
           → then corpus scan (loot refs + log lines)
           → fallback: intel_from_com_tasks()
    3. Match tasks to intel via task_name_hint
    4. Score each candidate (_score_com_task): zip+2, dll+1, non-system run_as+3; ComTaskScore.is_system_account flags service principals
    5. Check ACL writability (_WRITABLE_RE on acl_output)
    6. Severity: writable+known_run_as (non-system) → critical | strong_loot_hints (non-system) → high | system account → medium | else → info
    7. Emit TaskHijackFinding per unique task name
```

### Severity Rules (CRITICAL — do not change without updating tests)
```
critical  → writable=True AND run_as != "unknown" AND NOT a system service account AND drop_path is known
high      → strong_loot_hints=True (zip+dll from loot) OR drop_path == UNKNOWN_DROP_PATH (never critical)
medium    → SYSTEM / LocalService / NetworkService task — persistence value, not privilege escalation
info      → writable=False AND no strong loot hints
```

System service accounts (SYSTEM, LocalService, NetworkService) are **not** filtered out.
They surface as `medium` with evidence/detail: "Runs as SYSTEM — value is persistence, not escalation".

When `drop_path == UNKNOWN_DROP_PATH`, severity is capped at `high` even if ACL writability
was detected — the operator must confirm the drop path manually first.

`strong_loot_hints = bool(loot.zip_dll_refs or loot.dll_hijack_refs or (intel.payload_zip and intel.payload_dll))`

UNC (`\\server\share\...`) and forward-slash paths are parsed in `extract_hijack_intel()` after
the Windows drive-letter pass. If zip+dll are confirmed but no path parses, `drop_path` is set
to the sentinel `UNKNOWN_DROP_PATH`.

---

## DCSync Op Rules

```python
# From ACL findings:
for finding where right == "dcsync":
    if owned_user matches principal → emit op (severity: critical)

# Historical failure check:
exploit_log.json → steps[].phase == "dcsync" AND status == "failed"
    → downgrade ALL dcsync ops to severity="info"
    → set dcsync_failed=True on all dcsync ops

# Fallback (no ACL dcsync found but owned users + DCs exist):
emit one dcsync op with detail hinting secretsdump
if has_failed_dcsync: severity="info"
```

**Never** remove the `has_failed_dcsync` check — it prevents false-positive `critical` ops after a failed attempt.

---

## AdminTo Deduplication & Cap

```python
# In _prioritize_postex_ops():
adminto_cap = 3      # max 3 AdminTo ops surfaced to operator
```

Rationale: `adminto` ops are generated for up to 10 hosts from `_computer_targets()` + any attack-path targets. Without the cap the playbook becomes noise. Do not raise the cap without a filter mechanism.

---

## Local Shell Techniques — Assignment Rule

`sam_dump`, `lsa_secrets`, `lsass_dump`, `dpapi`, `rdp_creds` are **ONLY** assigned to `verified_admin_hosts`.

```python
# verified_admin_hosts resolution order:
1. Credentials with username ending in "$" → resolve_winrm_host_for_account()
2. Fallback IF owned users exist: dcs → computers[:1]
# Do NOT use a generic <local_shell> placeholder — emit nothing if no host is confirmed
```

---

## Shell Client (`shell_client.py`)

- `ReverseShellRepl.interact()` — raw TCP REPL; calls `post_connect_check()` before the prompt loop
- `ReverseShellRepl.post_connect_check()` — whoami, mark owned + graph refresh, priv check, next steps
- `ReverseShellRepl.run_local_scan()` — marks captured user as owned, then spawns `admapper <args>` subprocess
- `connect_shell()` — CLI entry for `admapper postex shell`; reads `listener.json` marker (valid 1 hour)
- `run_postex_handler()` — `admapper postex handler` persistent listener (`handler.py`)
- `load_or_start_listener()` — reuses in-process listener or refuses double-bind on occupied port

**Do not add session credential storage inside `shell_client.py`** — ownership marking goes through `escalate.analyze.mark_user_owned()`.

### Payload arch (`pe_arch.resolve_payload_arch`)

1. `--arch` CLI override
2. `postex_scan.json` → `finding.target_arch`
3. Monitor log error 193 → **x64**
4. Remote task executable PE arch (WinRM)
5. DC target → **x64**
6. Default **x64**

Deploy logs: `arch: x64 (cli --arch override)`

Upload order when callback IP is known: **HTTP staging first** (curl / IWR), then
evil-winrm, certutil b64, WinRM chunks. Defaults: `--arch x64`, `--generator msfvenom`.

**Upload principal ≠ task principal.** WinRM upload often runs as a gMSA (e.g.
`msa_health$`) while the scheduled task runs as an interactive user parsed from
`postex_scan.json` `tasks` / `com_task_raw` (e.g. `jaylee.clifton`). After upload,
`grant_task_read_acl` grants read on the ZIP to the task user.

Diagnostics: `admapper postex logs -w <workspace>` — remote ZIP status + monitor log tail.

Scheduled-task DLL hijacks that call a **named export** (e.g. `PreUpdateCheck`)
use **msfvenom shellcode** wrapped in a mingw stub exporting that name.
The export must run shellcode **synchronously** (block until the callback starts);
returning immediately lets the host unload the DLL and kill the shell thread.
Use `--generator mingw` for the legacy pure-mingw socket DLL.

### `listener.json` schema

`{"port": 4444, "timestamp": <unix>, "op_id": "postex-001", "connected": false, "peer": ""}`

Updated on callback with `"connected": true`. TTL 1h (`config.json` → `listener_ttl_seconds`).

`postex run` skips its own listener when an external handler already owns the port.

### Monitor log path — discover → variable → use

The service log path is **never hardcoded**. It flows through workspace artifacts:

```
postex scan (WinRM)
  _probe_service_logs()  →  (excerpt, winning_path)
  extract_hijack_intel()   →  paths parsed from log lines (optional)
  with_discovered_monitor_log_path()  →  HijackIntel.monitor_log_path
  analyze_task_hijack()    →  hijack_intel + top-level monitor_log_path
  postex_scan.json

postex run (wait loop)
  _resolve_monitor_log_path(scan, drop_path)
    1. scan["monitor_log_path"]
    2. scan["hijack_intel"]["monitor_log_path"]
    3. .log paths in monitor_log_excerpt
  _monitor_log_script(intel_path, drop_path)  →  poll tail via shell
```

Re-run `admapper postex scan -w <workspace>` after looting logs locally if WinRM
could not read the file — `extract_hijack_intel` can still infer the path from excerpt text.

### Handler pattern

Terminal 1: `admapper postex handler -w <workspace> --lport 4444`

Terminal 2: `admapper postex run --op postex-001 -w <workspace>` (upload + wait; handler catches shell)

---

## Artifacts Written

| File | Written by | Contents |
|------|-----------|----------|
| `postex_ops.json` | `run_postex_analysis()` | All opportunities + loot_intel |
| `postex_scan.json` | `remote_scan.py` | WinRM task scan results; includes `monitor_log_path` when a service log is probed |
| `listener.json` | `listener_marker.py` | port, op_id, connected, peer, timestamp |
| `exploit_log.json` | `exploit/` engine | Steps + status (read by postex for DCSync check) |

---

## Parsing Helpers — Do Not Duplicate

| Function | Location | Purpose |
|----------|----------|---------|
| `_parse_com_task_lines()` | `task_hijack.py` | pipe-delimited COM/nxc task output → `ScheduledTaskRecord` |
| `parse_schtasks_list_output()` | `hijack_intel.py` | `schtasks /query /fo LIST /v` → pipe format |
| `parse_task_xml_file_output()` | `hijack_intel.py` | Windows Task XML file → pipe format |
| `intel_from_com_tasks()` | `hijack_intel.py` | pipe lines → `HijackIntel` (scored) |
| `extract_hijack_intel()` | `hijack_intel.py` | loot + logs → `HijackIntel` |
| `guess_run_as_from_log()` | `hijack_intel.py` | regex infer run-as from service log |
| `strip_nxc_winrm_output()` | `nxc_output.py` | strip WinRM output noise prefix |
| `infer_arch_from_monitor_log()` | `pe_arch.py` | x64 on error 193; x86/x64 from log lines |
| `resolve_payload_arch()` | `pe_arch.py` | arch + reason string for deploy |

If you need to parse task output, **use these functions**. Do not write new regex parsers for the same formats.

---

## Adding a New Technique

1. Add entry to `POSTEX_TECHNIQUES` in `catalog.py` with all fields.
2. Add detection logic in `analyze.py::build_postex_opportunities()` using `_opportunity(key, ...)`.
3. Write a unit test in `tests/postex/` with a mocked workspace (no real AD needed).
4. Add entry to `findings.json` schema if it generates a finding.
5. Add guide entry in `admapper/guides/catalog.py` with matching key.

**Do not add technique metadata anywhere except `catalog.py`.**

---

## Common Mistakes to Avoid

- **Hardcoding domain/IP in detection logic** — all targets come from workspace artifacts or session.
- **Raising adminto_cap** without justification — it generates noise for operators.
- **Assigning local shell techniques to `<local_shell>`** — must be a real resolved host.
- **Duplicating HijackIntel parsing** — use `extract_hijack_intel()` as the single entry point.
- **Skipping `has_failed_dcsync` check** — this causes false-positive critical ops.
- **Modifying `postex_scan.json` schema** without updating `analysis_from_scan_payload()` — the two are tightly coupled.
- **Storing credentials in `shell_client.py`** — use `escalate.analyze.mark_user_owned()`.