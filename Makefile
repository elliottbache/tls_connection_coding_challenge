PY ?= python3
PIP ?= $(PY) -m pip
VENVDIR ?= .venv
ACTIVATE = . $(VENVDIR)/bin/activate
PKG = src

DEV_EXTRAS ?= dev

.PHONY: help
help:
	@echo "Common targets:"
	@echo "  make all             Makes all except run-server and run-client"
	@echo "  make clean           Remove caches and build artifacts"
	@echo "  make venv            Create virtualenv (.venv)"
	@echo "  make install-dev     Install project + dev deps"
	@echo "  make certs           Creates the certificates necessary for mTLS"
	@echo "  make build-cpp       Builds the C++ WORK challenge binary and places it in _bin"
	@echo "  make docs            Build Sphinx HTML docs"
	@echo "  make lint            Run ruff (lint), black --check, isort --check, codespell"
	@echo "  make format          Run ruff --fix, black, isort"
	@echo "  make typecheck       Run mypy"
	@echo "  make test            Run pytest"
	@echo "  make run-server      Run server (local)"
	@echo "  make run-client      Run client (local)"
	@echo "  make bench           Quick benchmark for pow (example)"

$(VENVDIR):
	$(PY) -m venv $(VENVDIR)

.PHONY: all
all: clean venv install-dev certs build-cpp docs lint format typecheck test bench

.PHONY: clean
clean:
	rm -rf .pytest_cache .mypy_cache **/__pycache__ docs/_build dist build *.egg-info .venv certificates docs/_autosummary

.PHONY: venv
venv: $(VENVDIR)
	@echo "Virtualenv created in $(VENVDIR)"

.PHONY: install-dev
install-dev: venv
	$(ACTIVATE); $(PIP) install --upgrade pip
	$(ACTIVATE); $(PIP) install -e .[$(DEV_EXTRAS)]

.PHONY: certs
certs:
	$(ACTIVATE); bash scripts/make-certs.sh

.PHONY: test
test:
	$(ACTIVATE); pytest -q

.PHONY: lint
lint:
	$(ACTIVATE); ruff check .
	$(ACTIVATE); isort --check-only --profile black src
	$(ACTIVATE); black --check --diff .
	$(ACTIVATE); codespell

.PHONY: format
format:
	$(ACTIVATE); ruff check . --fix
	$(ACTIVATE); isort --profile black .
	$(ACTIVATE); black .

.PHONY: typecheck
typecheck:
	$(ACTIVATE); mypy

.PHONY: docs
docs:
	$(ACTIVATE); mkdir -p docs/_build/doxygen
	$(ACTIVATE); doxygen docs/Doxyfile
	$(ACTIVATE); sphinx-build -a -E -b html docs docs/_build/html

.PHONY: build-cpp
build-cpp:
	$(ACTIVATE); cmake -S cpp -B build -DCMAKE_BUILD_TYPE=Release
	$(ACTIVATE); cmake --build build --config Release
	$(ACTIVATE); ctest --test-dir build --output-on-failure
	$(ACTIVATE); cmake --install build --prefix src



# Set a default value if the user doesn't provide one
token ?= gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFCAzuwkwLCRgIIq
diff ?= 5

.PHONY: test-cpp
test-cpp:
	$(ACTIVATE); ctest --test-dir build --output-on-failure

.PHONY: run-server
run-server:
	$(ACTIVATE); tlslp-server

.PHONY: run-client
run-client:
	$(ACTIVATE); tlslp-client

runs ?= 1
SHELL := /bin/bash
.ONESHELL:
.PHONY: bench
bench:
	$(ACTIVATE)
	python3 - <<'PY'
	import time
	import subprocess
	# Use the Make variable DIFF inside the Python block
	t0=time.time()
	[subprocess.run(["build/pow_challenge", "$(token)", "$(diff)"], check=True) for _ in range($(runs))]
	print(f"Difficulty: $(diff)")
	print("Elapsed:", time.time()-t0, "s")
	PY
