Developer setup and test instructions

This project uses a local Python virtual environment for development and testing.

Quick start

1. Create a virtual environment and install dependencies (editable):

   python3 -m venv .venv
   .venv/bin/python -m pip install --upgrade pip setuptools wheel
   .venv/bin/python -m pip install -e '.[dev]'

2. Run the lightweight test runner:

   PYTHONPATH=. .venv/bin/python3 scripts/run_unit_tests.py

Makefile targets below automate these steps.

Notes
- The project lists runtime dependencies in `pyproject.toml`.
- Use the Makefile targets to create the venv, install deps, and run tests.
