.PHONY: install install-dev install-venv uninstall reinstall test lint security audit

install:
	./scripts/install.sh

install-dev:
	./scripts/install.sh --dev

install-venv:
	./scripts/install.sh --venv

reinstall:
	./scripts/install.sh --force

uninstall:
	pipx uninstall admapper || true

test:
	python3 -m pytest -q

lint:
	python3 -m ruff check admapper tests

security:
	python3 -m bandit -r admapper -ll -q -x admapper/graph/game_html.py || true

audit:
	python3 -m pip install pip-audit
	python3 -m pip_audit
