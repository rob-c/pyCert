PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: help venv install dev test lint format check build clean

help:
	@echo "make venv      create the virtualenv and install pyCert (editable)"
	@echo "make dev       venv + test tooling"
	@echo "make test      run the test suite"
	@echo "make lint      ruff check"
	@echo "make format    ruff format + check"
	@echo "make build     build a wheel and sdist in dist/"
	@echo "make clean     remove caches and build artefacts"

venv:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e .

dev: venv
	$(BIN)/pip install -e ".[dev]"

install: venv

test:
	$(BIN)/pytest

lint:
	$(BIN)/ruff check src tests

format:
	$(BIN)/ruff format src tests
	$(BIN)/ruff check --fix src tests

check: lint test

build: dev
	$(BIN)/pip install build
	$(BIN)/python -m build

clean:
	rm -rf $(VENV) dist build *.egg-info src/*.egg-info .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
