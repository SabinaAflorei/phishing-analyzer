.PHONY: help venv install setup corpus ingest poll run test lint typecheck ci fmt clean status

VENV := .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Creeaza .venv daca lipseste
	@test -d $(VENV) || python3 -m venv $(VENV)

install: venv ## Creeaza venv-ul si instaleaza dependintele
	$(PIP) install -q -r requirements-dev.txt
	$(PIP) install -q -e .

setup: install ## Tot ce trebuie ca sa pornesti: venv, dependinte, configurare
	@test -f config/settings.yaml || cp config/settings.example.yaml config/settings.yaml
	@test -f config/company_domains.yaml || cp config/company_domains.example.yaml config/company_domains.yaml
	@test -f .env || cp .env.example .env
	@echo
	@echo "Gata. Urmatorul pas:"
	@echo "  1. editeaza config/company_domains.yaml cu domeniile reale"
	@echo "  2. make corpus     (doar daca nu ai corpusul real in corpus/eml/)"
	@echo "  3. make ingest && make run"

corpus: ## Genereaza corpusul SINTETIC (doar daca nu ai corpusul real)
	$(PY) scripts/make_synthetic_corpus.py

ingest: ## Un ciclu de ingestie din sursa configurata
	$(VENV)/bin/triage ingest

poll: ## Ingestie la interval, pana la Ctrl+C
	$(VENV)/bin/triage poll

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
