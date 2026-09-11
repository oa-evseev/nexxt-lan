VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(PYTHON) -m pip
ENV_STAMP := $(VENV)/.project-installed
DIST_DIR := dist
MAIN_DIST := $(DIST_DIR)/nexxt-lan
NATIVE_DIST := $(DIST_DIR)/nexxt-lan-native

.DEFAULT_GOAL := help

.PHONY: help env install clean distclean check test format format-check build build-native check-dist release-check

help:
	@echo "make env     Create a development environment"
	@echo "make test    Run the production test suite"
	@echo "make check   Verify production imports and tests"
	@echo "make format  Format production sources and tests"
	@echo "make build           Build sdist and pure-Python wheel for nexxt-lan"
	@echo "make build-native    Build sdist and platform wheel for nexxt-lan-native"
	@echo "make check-dist      Run twine check on all built artefacts"
	@echo "make release-check   Run checks and make clean, validated release builds"

$(PYTHON):
	python3 -m venv $(VENV)

$(ENV_STAMP): pyproject.toml setup.py native/pyproject.toml $(PYTHON)
	$(PIP) install --upgrade pip
	$(PIP) install -e '.[dev,discovery]'
	touch $@

env: $(ENV_STAMP)

install: env

test: env
	$(PYTHON) -m pytest -q

check: env
	$(PYTHON) -c 'import cryptography, nexxt, nexxt.udp_protocol, tuya_p2p'
	$(PYTHON) -m pytest -q

format: env
	$(PYTHON) -m black --workers 1 nexxt_lan.py nexxt tuya_p2p tests

format-check: env
	$(PYTHON) -m black --check --workers 1 nexxt_lan.py nexxt tuya_p2p tests

build: env
	rm -rf $(MAIN_DIST)
	$(PYTHON) -m build --outdir $(MAIN_DIST) .

build-native: env
	rm -rf $(NATIVE_DIST)
	$(PYTHON) -m build --outdir $(NATIVE_DIST) native/

check-dist: env
	$(PYTHON) -m twine check $(MAIN_DIST)/* $(NATIVE_DIST)/*

release-check: env
	$(MAKE) clean
	$(MAKE) test
	$(PYTHON) -c 'import cryptography, nexxt, nexxt.udp_protocol, tuya_p2p'
	$(MAKE) format-check
	$(MAKE) build
	$(MAKE) build-native
	$(MAKE) check-dist

clean:
	rm -rf build native/build dist *.egg-info native/*.egg-info .pytest_cache
	find . -path './$(VENV)' -prune -o -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -path './$(VENV)' -prune -o -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '*.so' -o -name '*.pyd' \) -exec rm -f {} +

distclean: clean
	rm -rf .venv
# BEGIN RGN MANAGED MAKE CONTRACT (v5)
include Makefile.rgn
.PHONY: review release
review: rgn-review
release: rgn-release
# END RGN MANAGED MAKE CONTRACT (v5)
