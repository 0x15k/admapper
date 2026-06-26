# ADMapper — Makefile
.PHONY: help install install-dev install-venv uninstall reinstall lint format doctor version clean

PYTHON ?= python3

# ── Default target ──────────────────────────────────────────────
help:  ## Show this help
	@printf "\033[1mADMapper — available targets:\033[0m\n\n"
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk -F ':.*## ' '{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ── Installation ────────────────────────────────────────────────
install:       ## Install globally via pipx (recommended)
	./scripts/install.sh

install-dev:   ## Install in .venv with dev extras (ruff/bandit)
	./scripts/install.sh --venv --dev

install-venv:  ## Install in .venv with full extras
	./scripts/install.sh --venv

reinstall:     ## Force reinstall via pipx
	./scripts/install.sh --force

uninstall:     ## Remove admapper from pipx and .venv
	./scripts/install.sh --uninstall

# ── Quality ─────────────────────────────────────────────────────
lint:          ## Run ruff linter
	$(PYTHON) -m ruff check admapper

format:        ## Auto-format code with ruff
	$(PYTHON) -m ruff format admapper
	$(PYTHON) -m ruff check --fix admapper

# ── Utilities ───────────────────────────────────────────────────
doctor:        ## Run admapper doctor to check installation
	admapper doctor

version:       ## Show current version
	@$(PYTHON) -c "from admapper import __version__; print(f'admapper v{__version__}')"

clean:         ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info .eggs/
	rm -rf .ruff_cache/ .pytest_cache/ .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	@echo "Cleaned."
