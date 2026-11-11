PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
JOBS ?= auto

.PHONY: help venv install dev test test-serial coverage lint format check selftest gui screenshots build package-macos package-linux package-test clean

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
	@echo "make package-macos   pyCertWiz.app and a .dmg for this Mac, in dist/"
	@echo "make package-linux   Linux bundle, AppImage, .deb, .rpm, Arch package (Docker; ARCH=x86_64|aarch64)"
	@echo "make package-test    install the Linux packages in clean containers and test them (IMAGE=, FORMAT=)"
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

package-macos:
	packaging/macos/build-app.sh

# Docker builds for this machine's architecture; ARCH=x86_64 on Apple silicon emulates.
ARCH ?= $(shell uname -m | sed 's/arm64/aarch64/')
BUILD_IMAGE = $(if $(filter aarch64,$(ARCH)),almalinux:10,almalinux:8)
DOCKER_PLATFORM = $(if $(filter aarch64,$(ARCH)),linux/arm64,linux/amd64)
package-linux:
	docker run --rm --platform $(DOCKER_PLATFORM) -v "$(CURDIR):/src" -w /src $(BUILD_IMAGE) packaging/linux/build.sh
	docker run --rm --platform $(DOCKER_PLATFORM) -v "$(CURDIR):/src" -w /src ubuntu:24.04 sh -c \
		'apt-get update -qq && apt-get install -y -qq curl ca-certificates binutils file >/dev/null && packaging/linux/package.sh $(ARCH)'

IMAGE ?= debian:13
FORMAT ?= deb
package-test:
	packaging/tests/container-test.sh $(IMAGE) $(FORMAT)

clean:
	rm -rf $(VENV) dist build *.egg-info src/*.egg-info .pytest_cache .ruff_cache .coverage htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
