PY ?= python3
PIP ?= $(PY) -m pip
VENVDIR ?= .venv
ACTIVATE = . $(VENVDIR)/bin/activate
PKG = src

DEV_EXTRAS ?= dev

.PHONY: help
help:
	@echo "Common targets:"
	@echo "  make venv            Create virtualenv (.venv)"
	@echo "  make install-dev     Install project + dev deps"
	@echo "  make test            Run pytest"
	@echo "  make lint            Run ruff (lint), black --check, isort --check, codespell"
	@echo "  make format          Run ruff --fix, black, isort"
	@echo "  make typecheck       Run mypy"
	@echo "  make docs            Build Sphinx HTML docs"
	@echo "  make run-server      Run server (local)"
	@echo "  make run-client      Run client (local)"
	@echo "  make bench           Quick benchmark for pow (example)"
	@echo "  make clean           Remove caches and build artifacts"

$(VENVDIR):
	$(PY) -m venv $(VENVDIR)

.PHONY: venv
venv: $(VENVDIR)
	@echo "Virtualenv created in $(VENVDIR)"

.PHONY: install-dev
install-dev: venv
	$(ACTIVATE); $(PIP) install --upgrade pip
	$(ACTIVATE); $(PIP) install -e .[$(DEV_EXTRAS)]

.PHONY: test
test:
	$(ACTIVATE); pytest -q src/tests

.PHONY: lint
lint:
	$(ACTIVATE); ruff check .
	$(ACTIVATE); isort --check-only src
	$(ACTIVATE); black --check --diff .
	$(ACTIVATE); codespell

.PHONY: format
format:
	$(ACTIVATE); ruff check . --fix
	$(ACTIVATE); black .
	$(ACTIVATE); isort .

.PHONY: typecheck
typecheck:
	$(ACTIVATE); mypy

.PHONY: docs
docs:
	$(ACTIVATE); sphinx-build -b html docs docs/_build/html

.PHONY: run-server
run-server:
	$(ACTIVATE); python -m src.server

.PHONY: run-client
run-client:
	$(ACTIVATE); python -m src.client

SHELL := /bin/bash
.ONESHELL:
.PHONY: bench
bench:
	$(ACTIVATE)
	python - <<'PY'
	import time
	import subprocess
	t0=time.time()
	subprocess.run(["build/pow_benchmark","testauth","4","2"], check=True)
	print("Elapsed:", time.time()-t0, "s")
	PY

.PHONY: clean
clean:
	rm -rf .pytest_cache .mypy_cache **/__pycache__ docs/_build dist build *.egg-info
