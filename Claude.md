ADMapper

All-in-one Active Directory pentesting CLI — enumerate, attack, and own AD environments.
Replicates and extends ADScan LITE (64 techniques), modular Python, no Docker required.
GitHub: https://github.com/0x15k/admapper | License: Apache 2.0

Stack


Python 3.11+ | typer (CLI/REPL) | rich (output) | ldap3 | impacket | dnspython | pytest | ruff
Entry point: admapper (installed via pipx)
State: JSON artifacts per workspace (workspaces/<name>/)


Commands

bash# Dev install (primary)
pip install -e ".[recon]"          # CORE + RECON tiers (macOS dev)
pip install -e ".[full]"           # includes WinRM + GSSAPI
pip install -e ".[dev]"            # + pytest, ruff, bandit

# Make targets
make lint          # ruff
make format        # ruff --fix
make security      # bandit
make doctor        # check installation health

# Run
admapper                           # interactive REPL
admapper run -H <DC_IP> -u <user> -p '<pass>'   # automated pipeline
admapper r -H <DC_IP> -u <user> -p '<pass>'     # alias

Architecture

See docs/PROJECT.md (source of truth — phases P0–P17, roadmap, all decisions).

Package layout in admapper/:

PackageRolecli/typer entrypoints + interactive shell dispatchcore/session, workspace, OPSEC profiles, output (rich)models/dataclasses: UserRecord, Credential, Finding, …recon/unauthenticated recon (DNS, null LDAP, SMB probes)enumeration/SAMR/LDAP/RID user enum + roastable detectioncreds/credential management, cracking, sprayingauth/authenticated LDAP+SMB enum, security postureacl/ACL/ACE enumeration and analysisadcs/AD CS detection ESC1–15kerberos/Kerberos attacks + timeroastcoerce/coercion playbook + NTLM relay auto-exploitexploit/exploitation engine (DCSync, RBCD, persistence, …)escalate/privilege escalation analysispostex/post-exploitation (DLL hijack, scheduled tasks)graph/web dashboard + attack graph (vis.js)report/export JSON / Navigator / HTMLguides/BloodHound-style manual exploitation guideschain/automated exploit chain enginemethodology/canonical phases P1–P12 (unified.py)

Each technique package follows the uniform interface: analyze.py · catalog.py · render.py.

Workspace Artifacts

Stored in workspaces/<engagement>/<domain>/ — never commit these.

Key files: users.json, credentials.json, graph.json, findings.json,
auth_inventory.json, security_posture.json, acl_findings.json,
adcs_findings.json, paths.json, bloodhound/, loot/.

Critical Rules


IMPORTANT: Never hardcode IPs, domain names, or lab-specific values. All targets come from workspace config or CLI args.
IMPORTANT: UI copy, placeholders, and docs must use generic enterprise AD examples only — never CTF/lab platform names (e.g. `.htb`, box codenames) or iconic lab VPN ranges (e.g. `10.10.11.x`) in examples shown to operators.
  - Workspace names: engagement codenames like `corp-internal`, `prod-forest` (not target IPs or lab box names).
  - Domains: `corp.local`, `ad.contoso.com`, `fabrikam.local`.
  - IPs: private RFC1918 ranges (`192.168.x.x`, `10.0.x.x`) — placeholders only; real targets always come from the workspace.
IMPORTANT: Never commit workspaces/ data — it contains credentials and hashes in plaintext by design.
Every new technique must: have an isolated module, unit tests with mocks, a JSON artifact, an entry in findings.json (severity + MITRE ID), and a direct CLI command.
Noisy actions (spray, exploit, dump, DCSync) MUST prompt for confirmation unless OPSEC profile is lab.
The web dashboard must never embed raw credentials in payloads sent to the frontend.
GUI actions map 1:1 to CLI commands — do not reimplement technique logic in the web layer.


Companion Tools (external, not in package)

Installed separately via pipx/brew/apt: certipy-ad, pywhisker, netexec (nxc), hashcat, john.
Do not attempt to install or manage these from within the package.

Platform Context

Primary dev: macOS + venv + pip install -e ".[recon]".
Tests run fully mocked — no real AD domain needed for CI.

## Agent Instructions (MANDATORY)

Before writing any code, modifying any file, or proposing any implementation:
1. Read this file completely
2. Read `admapper/skills/architecture.md`
3. If touching `postex/` or `escalate/`: read `admapper/skills/hijack_detection.md`
4. If touching `dashboard/` : read `admapper/skills/dashboard.md`

### Before fixing command execution, streaming, or terminal output

1. Read `admapper/skills/architecture.md` — **CLI Engine** and **Output and streaming** sections
2. Read `admapper/skills/dashboard.md` if touching `dashboard/`
3. Place fixes in the **engine layer** (`recon/`, `support/output.py`, `support/verbosity.py`,
   `cli/scan.py`) unless the bug is purely HTTP/SSE wiring
4. Dashboard must call `dispatch()` / engine functions — never reimplement technique logic

Do not proceed without completing these reads.

### DLL hijack — service logs (no hardcoded paths)

Service log paths come **only** from workspace intel: `hijack_intel.monitor_log_path`,
`monitor_log_excerpt` parsing, loot, or remote scan probes under the discovered
`drop_path`. Never hardcode vendor names, zip/dll filenames, or log basenames for
a specific lab. During `postex run`, poll the path recorded in `postex_scan.json`
or probe generic `Logs\*.log` candidates under `drop_path`.