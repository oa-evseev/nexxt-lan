VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(PYTHON) -m pip
ENV_STAMP := $(VENV)/.project-installed

.DEFAULT_GOAL := help

.PHONY: help env install check test format

help:
	@echo "make env     Create a development environment"
	@echo "make test    Run the production test suite"
	@echo "make check   Verify production imports and tests"
	@echo "make format  Format production sources and tests"

$(PYTHON):
	python3 -m venv $(VENV)

$(ENV_STAMP): pyproject.toml setup.py $(PYTHON)
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

clean:
	rm -rf build native/build dist *.egg-info native/*.egg-info .pytest_cache
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '*.so' -o -name '*.pyd' \) -delete

distclean: clean
	rm -rf .venv
