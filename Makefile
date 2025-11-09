PYTHON := python3
VENV_DIR := .venv
PY := $(VENV_DIR)/bin/python
PIP := $(VENV_DIR)/bin/pip

.PHONY: venv install test clean

venv:
	$(PYTHON) -m venv $(VENV_DIR)
	$(PY) -m pip install --upgrade pip setuptools wheel

install: venv
	$(PIP) install -e '.[dev]'

test: install
	PYTHONPATH=. $(PY) scripts/run_unit_tests.py

tests-log: install
	PYTHONPATH=. $(PY) scripts/run_unit_tests.py | tee tests.log

clean:
	rm -rf $(VENV_DIR) .pytest_cache tests.log
