# Atajos de desarrollo (Linux/macOS). En Windows usar los comandos equivalentes del README.
PYTHON ?= python3
VENV   ?= .venv
BIN    := $(VENV)/bin

.PHONY: help venv install lint format test cov run sample scripts-check clean

help:
	@echo "make install       crea el venv e instala dependencias de desarrollo"
	@echo "make lint          ruff check + ruff format --check"
	@echo "make format        aplica ruff format y fixes automáticos"
	@echo "make test          corre pytest"
	@echo "make cov           pytest con reporte de cobertura"
	@echo "make run           corre el diagnóstico con la config de ejemplo"
	@echo "make sample        regenera el reporte de ejemplo en docs/"
	@echo "make scripts-check bash -n + shellcheck sobre scripts/*.sh"

$(BIN)/python:
	$(PYTHON) -m venv $(VENV)

venv: $(BIN)/python

install: venv
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/pip install -r requirements-dev.txt

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

format:
	$(BIN)/ruff check --fix .
	$(BIN)/ruff format .

test:
	$(BIN)/pytest

cov:
	$(BIN)/pytest --cov --cov-report=term-missing

run:
	$(BIN)/sysdiag run -c config/sysdiag.example.yaml -o reports

sample:
	$(BIN)/python docs/generate_sample.py

scripts-check:
	bash -n scripts/*.sh
	shellcheck scripts/*.sh

clean:
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov reports build dist src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
