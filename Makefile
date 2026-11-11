PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
JOBS ?= auto

.PHONY: help venv install dev test test-serial coverage lint format check selftest gui screenshots build clean

help:
	@echo "make venv         create the virtualenv and install pyCertWiz (editable, with the GUI)"
	@echo "make dev          venv + test tooling (pytest, pytest-qt, pytest-xdist, ruff, build)"
	@echo "make test         run the test suite in parallel (JOBS=auto)"
	@echo "make test-serial  run the test suite in one process"
	@echo "make coverage     full suite with the 100% line and branch coverage gate (GUI included)"
	@echo "make lint         ruff check"
	@echo "make format       ruff format + autofix"
	@echo "make check        lint + test"
	@echo "make gui          start the desktop application"
	@echo "make screenshots  regenerate docs/images against a throw-away sandbox CA"
	@echo "make build        build a wheel and sdist in dist/"
	@echo "make clean        remove caches and build artefacts"

venv:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[gui]"

dev: venv
	$(BIN)/pip install -e ".[dev]"

install: venv

test:
	QT_QPA_PLATFORM=offscreen $(BIN)/pytest -n $(JOBS)

test-serial:
	QT_QPA_PLATFORM=offscreen $(BIN)/pytest

coverage:
	QT_QPA_PLATFORM=offscreen $(BIN)/pytest -n $(JOBS) --cov=src/pycert --cov-report=term-missing --cov-fail-under=100

lint:
	$(BIN)/ruff check src tests sandbox_ca

selftest:
	$(BIN)/pycert selftest

format:
	$(BIN)/ruff format src tests sandbox_ca
	$(BIN)/ruff check --fix src tests sandbox_ca

check: lint test

gui:
	$(BIN)/pycert gui

screenshots:
	QT_QPA_PLATFORM=offscreen $(BIN)/python tools/screenshots.py docs/images

build: dev
	$(BIN)/python -m build

clean:
	rm -rf $(VENV) dist build *.egg-info src/*.egg-info .pytest_cache .ruff_cache .coverage htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
