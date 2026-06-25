---
name: admapper-testing-standards
description: Execution guidelines, local virtual environments usage, and QA standards for running tests inside the ADMapper repository.
---

# ADMapper Testing & QA Standards

This skill defines the environment, tool usage, and design guidelines for testing ADMapper components.

## 1. Virtual Environment & Python Interpreter
- **Environment Choice**:
  - Always run tests inside the `.venv` or `.venv313` folder to ensure modern Python compatibility (Python >= 3.11).
  - Do NOT run global `pytest` because the default system Python (often 3.9 on macOS Developer Tools) lacks `enum.StrEnum` and other modern standard library features, leading to collection crashes.
- **Command prefix**:
  - Propose/run: `.venv/bin/pytest`

## 2. Test Structure and Practices
- **Mocking External Services**:
  - Active Directory operations (LDAP lookups, SMB connections, Ticket forging) should be mocked in unit tests.
  - See existing mocks in `tests/test_adcs.py` or `tests/test_acl_abuse.py`.
- **Clock Skew Mocks**:
  - Since Kerberos relies heavily on the clock, test cases checking `faketime` offset or time sync prompts should mock `get_clock_skew` or target system time.

## 3. Dependency Verification Check
- Use `admapper doctor` to quickly verify if required binaries (e.g. `nxc`, `evil-winrm`, `faketime`) are missing or incorrectly linked on the local machine before performing integration test checks.
