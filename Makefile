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
	@echo "  make setup           Makes those needed for initial setup"
	@echo "  make ci              Makes those needed for CI (lint, typecheck, test)"
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
	@echo "  make test-cpp        Run CTest"
	@echo "  make run-server      Run server (local)"
	@echo "  make run-client      Run client (local)"
	@echo "  make bench           Quick benchmark for pow (example)"

$(VENVDIR):
	$(PY) -m venv $(VENVDIR)

.PHONY: all
all: clean install-dev certs build-cpp docs lint format typecheck
	$(ACTIVATE); pytest -q --no-persistent-logs
	$(ACTIVATE); make bench --no-print-directory

.PHONY: setup
setup: install-dev certs build-cpp

.PHONY: ci
ci: lint typecheck test

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
	bash scripts/make-certs.sh

.PHONY: build-cpp
build-cpp:
	cmake -S cpp -B build -DCMAKE_BUILD_TYPE=Release
	cmake --build build --config Release
	ctest --test-dir build --output-on-failure
	cmake --install build --prefix src

.PHONY: docs
docs: install-dev
	$(ACTIVATE); mkdir -p docs/_build/doxygen
	$(ACTIVATE); doxygen docs/Doxyfile
	$(ACTIVATE); sphinx-build -a -E -b html docs docs/_build/html

.PHONY: lint
lint: install-dev
	$(ACTIVATE); ruff check .
	$(ACTIVATE); isort --check-only --profile black src
	$(ACTIVATE); black --check --diff .
	$(ACTIVATE); codespell

.PHONY: format
format: install-dev
	$(ACTIVATE); ruff check . --fix
	$(ACTIVATE); isort --profile black .
	$(ACTIVATE); black .

.PHONY: typecheck
typecheck: install-dev
	$(ACTIVATE); mypy

.PHONY: test
test: install-dev
	$(ACTIVATE); pytest -q

.PHONY: test-cpp
test-cpp: build-cpp
	ctest --test-dir build --output-on-failure

.PHONY: run-server
run-server: setup
	$(ACTIVATE); tlslp-server --log-level=DEBUG

.PHONY: run-client
run-client: setup
	$(ACTIVATE); tlslp-client --log-level=DEBUG

# set a default value if the user doesn't provide one
token ?= gkcjcibIFynKssuJnJpSrgvawiVjLjEbdFuYQzuWROTeTaSmqFCAzuwkwLCRgIIq
diff ?= 5
runs ?= 1
SHELL := /bin/bash
.ONESHELL:
.PHONY: bench
bench: build-cpp
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
