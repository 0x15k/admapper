# SKILL: Dashboard

Read this file completely before touching any module under `admapper/dashboard/`.

**Read `admapper/skills/architecture.md` first** — especially *CLI Engine* and *Dashboard = consumer only*.

---

## Dashboard vs CLI Engine

The dashboard is a **consumer** of the CLI engine, not a second implementation.

| Concern | Correct layer |
|---------|----------------|
| Discovery / unauth recon | `dispatch(session, 'start_unauth')` → `recon/unauth.py` |
| Post-scan summary | `cli/scan.print_scan_summary(session)` inside `_run_workspace_script` |
| Live scan output | `support/output.py` + `support/verbosity.py` (streamed via `DashboardStream`) |
| Terminal noise / dedupe | `terminal_filter.py` |
| Op orchestration, SSE, progress flags | `dashboard_server.py` only |

Never add dashboard-only LDAP/DNS logic or a parallel `_emit_scan_summary`. If compact
output is missing, extend `print_scan_summary` or `quiet_*` in the engine layer.

---

## Module Map

```
admapper/dashboard/
├── dashboard_server.py      # HTTP server (stdlib only) + DashboardContext orchestrator
├── dashboard_html.py        # build_dashboard_html() — SPA entry point, injects all modules
├── ops_html.py              # build_ops_html() / write_ops_html() — standalone HTML export
├── ops_payload.py           # build_ops_payload() — the single source of truth for all UI state
├── ops_ui.py                # build_ops_payload() alias + UI-layer helpers (imported by ops_payload)
├── ops_state.py             # build_objective_ops_state() — phase gating, missions, actions
├── ops_progress.py          # OpsProgress — persistent engagement progress (ops_progress.json)
├── dashboard_auth.py        # run_dashboard_credential_auth() — credential verify from dashboard
├── dashboard_winrm.py       # WinRM PTH helper for dashboard context
├── sharphound_import.py     # Feature 1 — SharpHound ZIP overlay (CSS/JS/HTML strings only)
├── bloodhound_overlay.py    # Feature 1 — bloodhound-python overlay merge + collect UI
├── command_cheatsheet.py    # Feature 2 — live variable substitution command reference
└── terminal_filter.py       # TerminalFilter — strips ANSI/rich output for SSE terminal
```

---

## Architecture: Request → Response

```
Browser → GET /
    dashboard_server.py::DashboardHandler.do_GET()
    → build_dashboard_html()   (dashboard_html.py)
    → injects OPS payload as window.__OPS JSON
    → serves SPA (single HTML file, no static assets)

Browser → GET /api/state
    → DashboardContext.refresh_payload()
    → build_ops_payload()      (ops_payload.py)
    → returns JSON

Browser → POST /api/<action>
    → DashboardContext._start_background(fn)
    → fn runs in a daemon thread (op_lock prevents concurrent ops)
    → ops emit lines to ctx.events queue
    → GET /api/events (SSE) streams them to terminal

Browser → GET /api/events
    → SSE loop, streams ctx.events.queue items as JSON
    → {"type": "log|cmd|phase|error|done|state", "line": "...", "ts": ...}
    → type="state" with {"refresh":true} triggers client-side refreshAfterOp()
```

---

## DashboardContext — State Machine

`DashboardContext` is the per-server singleton. All workspace state lives here.

**Key fields:**
```python
ws_path: Path               # workspaces/<name>/
workspace: str
domain: str | None
owned_users: list[str]      # merged from state.json + credentials.json + progress
_initial_owned_users: list[str]   # set at startup, never overwritten
pivot_user: str | None      # active pivot identity
events: queue.Queue         # SSE event bus
op_lock: threading.Lock     # only one op at a time
running: bool               # True while a background op is active
progress: OpsProgress       # persisted phase flags
terminal_filter: TerminalFilter
```

**Credential sync priority** (in `refresh_payload()`):
1. `ops_progress.json` owned_users
2. `state.json` owned_users + pivot_user + domain + hosts
3. `credentials.json` valid credentials
4. `_initial_owned_users` (always merged in, never lost)

**IMPORTANT:** Never replace `_initial_owned_users` once set. It holds context
established via CLI flags (`admapper dashboard -u <user>`) that would otherwise
be lost after the first `refresh_payload()` call.

---

## ops_payload.py — build_ops_payload()

**This is the single source of truth for all dashboard UI state.**

Returns a dict with these top-level keys (all consumed by the SPA):

```python
{
  "meta":                 # workspace, domain, dc_ip, dc_host, blackbox flag
  "topology":             # network topology (infra nodes, not AD objects)
  "graph_mode":           # "network" | "hybrid" — drives which tab is default
  "player":               # pivot, owned, owned_methods
  "selectable_identities": # list of user profiles with lens data
  "identity_lens":        # full lens for current pivot
  "phases":               # phase status bar (P1-P12)
  "dashboard":            # ops_state (missions, actions, next_edge)
  "mission":              # primary mission card
  "quests":               # ACL/PrivEsc missions list
  "attack_paths":         # from paths.json, filtered for pivot
  "quick_wins":           # from paths.json quick_wins
  "actions":              # enabled action buttons
  "objective":            # next hop headline + command
  "methodology":          # methodology lines for framework bar
  "highlights":           # enum highlights (shown after enum_users)
  "clues":                # loot clues filtered
  "creds":                # credential inventory
  "hashes":               # gained NTLM hashes
  "pth_sessions":         # WinRM PTH ready sessions
  "progress":             # {scan, enum_users, loot, acls, exploit} booleans
  "effective_progress":   # workspace-hydrated flags (CLI run sync — prefer over progress)
  "next_action":          # {command, headline, reason, impact, source, ...}
  "graph":                # vis.js graph payload (nodes + edges)
  "engagement_intel":     # full intel dict for reference panel
  "findings":             # findings.json contents
  "operator_setup":       # local prep (clock sync, gssapi, hosts entry)
  "engagement_framework": # string shown in framework bar
  "study_map":            # CRTP/CRTE/CRTO/MITRE reference table
  "pentest_book":         # technique book (pages + chapters)
}
```

**Do NOT add keys that duplicate existing ones.** If you need new data in the UI,
extend an existing sub-dict or add a new top-level key with a clear name.

---

## API Endpoints

| Method | Path | Handler | Background? |
|--------|------|---------|-------------|
| GET | `/` | `build_dashboard_html()` | No |
| GET | `/api/state` | `ctx.refresh_payload()` | No |
| GET | `/api/events` | SSE stream from `ctx.events` | Blocking |
| POST | `/api/scan` | `ctx.run_scan(ip=)` | Yes |
| POST | `/api/run` | `ctx.run_auth(username, password, ip)` | Yes |
| POST | `/api/enum` | `ctx.run_enum_users()` → `run_domain_enumeration()` | Yes |
| POST | `/api/asreproast` | `ctx.run_asreproast()` | Yes |
| POST | `/api/kerberoast` | `ctx.run_kerberoast()` | Yes |
| POST | `/api/spray` | `ctx.run_spray(password)` | Yes |
| POST | `/api/exploit` | `ctx.run_exploit()` | Yes |
| POST | `/api/acls` | `ctx.run_acls()` | Yes |
| POST | `/api/pivot` | `ctx.set_pivot(username)` | No (sync) |
| POST | `/api/winrm` | `ctx.run_winrm_pth(account)` | Yes |
| POST | `/api/brief` | `ctx.run_brief(auto=)` | Yes |
| POST | `/api/bloodhound` | `ctx.run_bloodhound_collect(collect=)` | Yes |
| POST | `/api/import` | `ctx.import_parser_items(items)` | No (sync) |

**Adding a new endpoint:**
1. Add `POST /api/<name>` handler in `DashboardHandler.do_POST()`
2. Add corresponding method in `DashboardContext`
3. Use `_start_background()` for anything that runs a CLI command
4. Use `_run_workspace_script()` for in-process ops (preferred — routes stdout through terminal filter)
5. Use `_run_subprocess()` for external binary calls only

**Never add GET endpoints that modify state.** Only POST triggers ops.

---

## Background Op Pattern

```python
# Correct pattern for adding a new background op:
def run_my_op(self) -> None:
    ok = self._run_workspace_script(
        "from admapper.cli.commands import dispatch\n"
        "dispatch(session, 'my_command')",
        label="my_command",
    )
    if ok:
        self.progress.some_flag = True
        self._sync_some_owned()   # if creds are gained
        self.progress.save(self.ws_path)

# In do_POST():
if path == "/api/my_op":
    self._start_background(ctx.run_my_op)
    return
```

**IMPORTANT:** `_run_workspace_script()` executes Python code with `exec()` in a
`Session` context. The `session` variable is pre-bound. Never use `_run_subprocess()`
for pure Python ops — it spawns a new process unnecessarily.

---

## Credential Sync Methods

After any op that gains credentials, call the appropriate sync:

| Sync method | When to call |
|-------------|-------------|
| `_sync_spray_owned()` | After `run_spray()` — reads `spray_report.json` |
| `_sync_exploit_owned()` | After `run_exploit()` — reads `exploit_log.json` |
| `_sync_new_creds_owned(source, method)` | After roast ops — reads `credentials.json` filtered by source |
| `_sync_offline_cracked_hashes()` | Called automatically in `refresh_payload()` — reads `loot/cracked.txt` |

**Do not** directly append to `self.owned_users` without also calling
`self.progress.remember_owned(user, method=...)` and `self.progress.save()`.

---

## OpsProgress

Persisted to `ops_progress.json` in the workspace. Controls phase gating.

```python
scan: bool              # start_unauth completed
enum_users: bool        # enum users/auth completed
loot: bool              # loot detected (set by _sync_loot_progress)
acls: bool              # acls completed
exploit: bool           # exploit completed
owned_users: list[str]
verified_users: list[str]
owned_methods: dict[str, str]   # username → "spray"|"kerberoast"|"password"|etc.
```

**Phase gates** (enforced in `ops_state.py`):
- Actions are disabled if their prerequisite phase flag is False
- `enum_users` gates: acls, adcs, spray, kerberoast, asreproast
- `acls` gates: exploit
- `exploit` gates: hashes shown in UI

---

## SSE Terminal Events

Every line emitted to `ctx.events` becomes a terminal line in the SPA:

```python
ctx.emit("some line", kind="log")    # white text
ctx.emit("✓ done", kind="done")      # triggers refreshAfterOp() + green flash
ctx.emit("✗ error", kind="error")    # red text
ctx.emit("→ phase", kind="phase")    # orange text
ctx.emit("cmd string", kind="cmd")   # accent color (shown as command)
ctx.emit(json.dumps({"refresh": True}), kind="state")  # triggers client refresh
```

`TerminalFilter` strips ANSI codes, rich markup, and progress bars from subprocess
stdout before emitting. Do not emit raw subprocess output directly.

---

## SharpHound Import (Feature 1 — sharphound_import.py)

**Presentation-only module.** Contains only CSS/HTML/JS string constants injected
into the SPA by `dashboard_html.build_dashboard_html()`.

**Design constraints (do not violate):**
- Parsing is 100% client-side via JSZip (CDN) — **no backend route**
- `graph.json` is **never replaced** — SharpHound data is an overlay only
- Overlay node IDs are namespaced `sh:` / `she:` — never collide with live graph
- `SharpHoundImport.overlayFor()` is called from `setGraphFilter()` — survives refreshes
- Max 2000 nodes / 4000 edges per import (hardcoded in JS as `MAX_NODES`/`MAX_EDGES`)

**If you need to add backend support** (e.g. persist to workspace), add a new
endpoint `/api/sharphound` that writes to `sharphound_overlay.json` and have
`build_ops_payload()` include it. Do not modify `sharphound_import.py` for backend logic.

---

## BloodHound Collection (Feature 1 — bloodhound-python)

**Primary module:** `admapper/auth/bloodhound_collect.py`  
**Overlay merge:** `admapper/dashboard/bloodhound_overlay.py`  
**Dashboard trigger:** `POST /api/bloodhound` → `DashboardContext.run_bloodhound_collect()`

### What exists today

| Source | When | Output |
|--------|------|--------|
| `export_bloodhound_minimal()` in `auth/bloodhound_export.py` | During `start_auth` / `run_auth_enumeration` | Minimal CE JSON (`users`, `groups`, `computers` only — no ACLs/sessions) |
| `run_bloodhound_collect()` | Dashboard **BH Collect** button or `POST /api/bloodhound` | Full bloodhound-python collection (`-c All` default) |

`start_auth` does **not** invoke bloodhound-python automatically — only the minimal LDAP
inventory export. Full collection is operator-triggered from the dashboard (or CLI via
`run_bloodhound_collect(session)`).

### Collection flow

```
POST /api/bloodhound  {"collect": "All"}   # or "DCOnly" for stealth LDAP-only
  → DashboardContext.run_bloodhound_collect()
  → _run_workspace_script("run_bloodhound_collect(session, collect=...)")
  → subprocess: bloodhound-python -d DOMAIN -u USER -p PASS -ns DC_IP -c All -op bloodhound/admapper
  → JSON files written to workspaces/<name>/bloodhound/
  → build_and_save_overlay() → workspaces/<name>/bloodhound_overlay.json
  → SSE "done" → client refreshState() → graph.bloodhound_overlay in /api/state
```

**Credentials:** uses workspace `credentials.json` (first valid cred, same as `start_auth`).
Supports password, NTLM (`--hashes`), and Kerberos (`-k --no-pass`).

**External binary:** `bloodhound-python` or `bloodhound` on PATH (`resolve_executable`).
Use the [bloodhound-ce branch](https://github.com/dirkjanm/BloodHound.py/tree/bloodhound-ce)
for BloodHound CE compatibility.

### Output paths

| Path | Purpose |
|------|---------|
| `bloodhound/admapper_*.json` | Raw bloodhound-python collector output (CE format) |
| `bloodhound/collection_manifest.json` | Run metadata (timestamp, cred id, file list) |
| `bloodhound_overlay.json` | vis.js overlay payload (workspace root, **not** inside `bloodhound/`) |

`graph.json` is **never** modified by collection — overlay only.

### Overlay merge

`build_ops_payload()` calls `load_overlay_for_payload(ws_path)` and attaches:

```python
graph["bloodhound_overlay"] = {
  "nodes": [{"id": "bh:S-1-5-...", "shape": "diamond", ...}],
  "edges": [{"id": "bhe:...", "from": "bh:...", "to": "bh:...", ...}],
  "meta": {"node_count": N, "edge_count": M, "source": "bloodhound-python"}
}
```

The SPA `BloodHoundOverlay` IIFE (in `bloodhound_overlay.py`) reads this on
`renderState()` and merges via `overlayFor()` inside `setGraphFilter()`.

**ID namespaces:**
- Server overlay: `bh:` / `bhe:` (bloodhound-python collection)
- Client ZIP import: `sh:` / `she:` (`sharphound_import.py` — manual fallback)

### `/api/bloodhound` contract

**Request:**
```json
{ "collect": "All" }
```
`collect` optional — `"All"` (default) or `"DCOnly"` (LDAP-only, quieter).

**Response:** `202` via background op pattern (no JSON body on POST). Terminal SSE streams
progress; `kind=done` triggers `refreshAfterOp()` → `GET /api/state`.

**Prerequisites:** valid credential in workspace, DC IP from `state.json` / scan.

### Next Best Action (`next_action.py`)

The **Next Best Action** card hydrates progress from workspace artifacts on each
`/api/state` refresh, then picks a command in priority order: **postex** →
**objective** → **mission** → **phase** → **fallback**. Running `admapper run`
then `admapper web` no longer shows stale `scan -H` when exploit/postex data exists.

### Gaps vs SharpHound

| Capability | Minimal export (`auth_enum`) | bloodhound-python `-c All` |
|------------|---------------------------|---------------------------|
| Users/groups/computers | ✅ | ✅ |
| ACLs / ACE edges | ❌ | ✅ |
| Sessions / local admins | ❌ | ✅ |
| Trusts / GPO / OU | partial (LDAP inventory) | ✅ |

---

## Graph Payload

`build_graph_payload()` (in `admapper/dashboard/web.py`) builds the vis.js graph
from `graph.json`. The result is enriched by `build_ops_payload()` with:

- `_tag_graph_paths()` — highlights edges that belong to computed attack paths
- `_enrich_graph_for_recon()` — adds placeholder DC node when graph is empty
- `graphFocus` / `infraFocus` — client-side selection state (not server-side)

**Node ID conventions:**
```
user:<username>@<domain>     # domain user
host:<address>               # infrastructure host
computer:<dn>                # AD computer object
gmsa:<name>                  # gMSA account
dc:<address>                 # domain controller placeholder
operator                     # operator node
```

**Do not** generate node IDs that don't follow these conventions — the client
uses them for identity matching in `parseUsernameFromNode()` and `focusIdentity()`.

---

## Identity Lens

`build_identity_lens()` (`admapper/graph/identity_lens.py`) builds a per-user
context dict included in `selectable_identities[].lens`. The lens drives:

- Profile panel in the left sidebar
- Filtered attack paths for the selected identity
- Filtered actions (pivot-specific vs global)
- Filtered quests (ACL opportunities for this user)

**Lens is expensive.** It is built for every selectable identity on each
`refresh_payload()` call. Do not add expensive operations inside
`build_identity_lens()` without profiling.

---

## Security Rules

- **Credentials masked in terminal:** `_compact_cmd()` replaces `-p <value>` with `-p '***'`
- **Credentials masked in SSE:** `TerminalFilter` strips secrets from subprocess stdout
- **Credentials NOT embedded in frontend payloads:** `build_ops_payload()` only
  includes `{user, status, source}` in `creds[]` — never the raw secret
- **Workspace path not exposed:** HTML title uses workspace name only, not path
- **No CORS:** server binds to `127.0.0.1` only — not accessible from LAN

---

## Common Mistakes to Avoid

- **Adding logic to `ops_html.py`** — it's a thin wrapper around `build_ops_payload()`.
  All logic goes in `ops_payload.py` or `ops_state.py`.
- **Replacing `graph.json` from the dashboard** — overlays are additive only.
  `graph.json` is written exclusively by `admapper/graph/build.py`.
  SharpHound ZIP imports are a client-side layer (`sh:` prefix).
  bloodhound-python collection writes to `bloodhound_overlay.json` via
  `/api/bloodhound` and is merged server-side — never replaces `graph.json`.
- **Calling `refresh_payload()` inside a background op thread** — this causes a
  race condition. The background op emits `{"refresh": True}` and the client
  triggers `/api/state` itself.
- **Raising `op_lock` timeout** — `op_lock.acquire(blocking=False)` returns 409
  immediately if busy. Never block on it.
- **Writing credentials to the events queue** — `ctx.emit()` goes to SSE which
  is readable by anyone with localhost access. Use `_compact_cmd()` for commands.
- **Importing from `admapper/graph/` in `sharphound_import.py`** — that module
  is presentation-only and must have zero ADMapper imports.
- **Using `_run_subprocess()` for Python ops** — use `_run_workspace_script()` instead.
- **Modifying `_initial_owned_users`** after `__init__` — it's the fallback anchor.

## UI copy and placeholders

Dashboard hints, modal text, and input placeholders must read like a professional AD assessment tool — not a CTF writeup.

| Field | Good examples | Avoid |
|-------|---------------|-------|
| Workspace name | `corp-internal`, `prod-forest` | Box names, `.htb` domains, target IPs |
| Domain | `corp.local`, `ad.contoso.com` | Lab-specific FQDNs |
| DC / target IP | `192.168.10.10`, `10.0.0.10` | `10.10.11.x` and other iconic lab VPN targets |
| Attacker IP | `192.168.1.50` | Lab VPN callback ranges in visible copy |

Real values always come from workspace state or operator input — placeholders are illustrative only.