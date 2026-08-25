.PHONY: help venv install run test lint typecheck ci fmt clean status

VENV := .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Instaleaza dependintele in venv
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .

run: ## Porneste dashboard-ul pe 127.0.0.1:8000
	$(VENV)/bin/uvicorn triage.dashboard.app:app --host 127.0.0.1 --port 8000 --reload

test: ## Ruleaza testele (retea blocata by default)
	$(VENV)/bin/pytest

lint: ## ruff
	$(VENV)/bin/ruff check src tests scripts
	$(VENV)/bin/ruff format --check src tests scripts

fmt: ## formateaza
	$(VENV)/bin/ruff format src tests scripts
	$(VENV)/bin/ruff check --fix src tests scripts

status: ## Panou de progres -> build/status.html
	$(PY) scripts/status.py

typecheck: ## mypy
	$(VENV)/bin/mypy

ci: lint typecheck test ## tot ce trebuie sa fie verde inainte de PR

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
