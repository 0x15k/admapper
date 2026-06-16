# AGENTS.md

## Cursor Cloud specific instructions

ADMapper is a single Python 3.11+ CLI package (no server/DB). Source in `admapper/`, tests in `tests/`. Standard dev commands live in the `Makefile`, run/usage in `README.md`, deps in `pyproject.toml`.

### Environment
- The dev environment is a venv at `.venv` installed editable with the `dev` extra (`pip install -e ".[dev]"`). The update script recreates/refreshes it on startup.
- Always activate it first: `source .venv/bin/activate`. Running `.venv/bin/admapper` without activating makes `doctor` warn `pip_not_in_venv` (cosmetic only).
- Editable install means source edits under `admapper/` take effect immediately; no reinstall needed unless dependencies in `pyproject.toml` change.

### Run / lint / test / security
- Run CLI: `admapper version`, `admapper doctor`, `admapper start` (interactive REPL), or `python3 -m admapper`. Do not run `python3 admapper/cli/run.py` directly (internal module).
- Lint: `make lint` (`ruff check admapper tests`). Test: `make test` (`pytest`). Security: `make security` (`bandit`, wrapped in `|| true`).
- Tests run fully offline (LDAP/SMB mocked, config isolated via `tests/conftest.py`). No external services, DB, or AD target needed for the test suite.

### Known caveats (pre-existing, not environment problems)
- `make lint` reports pre-existing ruff errors in committed code; `make security` reports pre-existing bandit findings (non-fatal by design).
- A few tests are macOS-oriented and fail on Linux because they assert macOS-only commands (e.g. `test_game_mode.py::test_operator_setup_hints` expects `sudo sntp`; `test_kerberos_skew`, `test_game_ui`). `test_winrm_upload.py::test_upload_falls_back_to_certutil` needs the optional `nxc`/netexec binary (not a pip dep). The remaining ~258 tests pass.
- Optional external binaries (`nxc`/netexec, `hashcat`, `john`, `kerbrute`, `evil-winrm`, `certipy`, `bloodhound-python`, `faketime`) are intentionally not pip deps and are absent; `admapper doctor` lists them. They are only needed for real AD engagements.
- Real end-to-end engagement runs (`admapper run -H <DC_IP> ...`) require an external Active Directory Domain Controller that is not part of this repo and cannot be provisioned here. Workspace/credential/session state is persisted as JSON under `~/.admapper/workspaces/`.
