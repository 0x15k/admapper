.PHONY: install install-dev install-venv uninstall reinstall test lint

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
	python3 -m pytest

lint:
	python3 -m ruff check admapper tests
