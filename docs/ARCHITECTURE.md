# ADMapper architecture

## Layout

```
admapper/
  core/           Session, workspace, paths, credentials store, output
  models/         Dataclasses (Credential, UserRecord, …)
  methodology/    Canonical engagement phases (P1–P12)
  analysis/       Operator intel: readiness, vectors, user_match, password rules
  cli/            Typer entrypoints and shell dispatch
  recon/          Unauthenticated discovery
  enum_pkg/       User enumeration (SAMR, LDAP) — rename candidate: enumeration/
  creds/          Roast, spray, verify, Kerberos skew
  auth/           Authenticated LDAP/SMB enum, BloodHound export
  graph/          Attack graph + dashboard UI (ops_payload, ops_html, dashboard_server)
  exploit/        Automated exploit chain
  escalate/       Pivot and next-hop edges
  guides/         Manual technique catalog and pentest book
  report/         Engagement map, export, MITRE Navigator
  <technique>/    Domain modules: acl, adcs, kerberos, coerce, cves, mssql, postex, wsus, winrm
```

Each technique package typically provides:

- `analyze.py` — workspace findings from JSON artifacts
- `catalog.py` — technique metadata and MITRE ids
- `render.py` — CLI display helpers

## Data flow

1. **Workspace** (`~/.admapper/workspaces/<name>/`) holds JSON artifacts only — never commit workspaces.
2. **Scan / run** write `unauth_scan.json`, `credentials.json`, `auth_inventory.json`, …
3. **Analysis** builds `engagement_intel`, attack vectors, and ops payload from artifacts.
4. **Dashboard** (`admapper dashboard`) serves UI from `dashboard_server` + `ops_payload`; ops spawn CLI subprocesses.

## Phases

Single canonical model: `methodology/unified.py` (P1–P12). Ops bar shows 9 steps mapped to P1–P12.

## Security

- Secrets live in workspace `credentials.json` (plaintext by design — local operator machine).
- Generated HTML (`ad_ops.html`, `attack_graph.html`) must stay under the workspace directory.
- Dashboard mode masks passwords in terminal output; do not embed secrets in dashboard JSON payloads.
