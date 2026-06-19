# ADMapper — Makefile
# ──────────────────────────────────────────────────────────────
.PHONY: help install install-dev install-venv uninstall reinstall \
        test lint format security audit clean doctor version

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

install-dev:   ## Install in .venv with dev extras (pytest/ruff)
	./scripts/install.sh --dev

install-venv:  ## Install in .venv with full extras
	./scripts/install.sh --venv

reinstall:     ## Force reinstall via pipx
	./scripts/install.sh --force

uninstall:     ## Remove admapper from pipx and .venv
	./scripts/install.sh --uninstall

# ── Quality ─────────────────────────────────────────────────────
test:          ## Run test suite
	$(PYTHON) -m pytest -q

lint:          ## Run ruff linter
	$(PYTHON) -m ruff check admapper tests

format:        ## Auto-format code with ruff
	$(PYTHON) -m ruff format admapper tests
	$(PYTHON) -m ruff check --fix admapper tests

security:      ## Run bandit security scan
	$(PYTHON) -m bandit -r admapper -ll -q -x admapper/graph/game_html.py || true

audit:         ## Audit pip dependencies for known CVEs
	$(PYTHON) -m pip install -q pip-audit
	$(PYTHON) -m pip_audit

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

# ── Docker (optional) ──────────────────────────────────────────
.PHONY: docker docker-run

docker:        ## Build Docker image
	docker build -t admapper:latest .

docker-run:    ## Run admapper in Docker (pass ARGS="...")
	docker run --rm -it -v "$(PWD)/workspaces:/app/workspaces" \
		admapper:latest $(ARGS)
