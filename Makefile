.PHONY: help venv install setup corpus ingest poll run test lint typecheck ci fmt clean

VENV := .venv

# Un venv isi pune executabilele in `bin/` pe Linux si macOS, si in `Scripts/`
# pe Windows. Fara ramura asta, fiecare tinta pica pe masina de dezvoltare cu
# "No such file or directory" - iar dezvoltarea se face si pe Windows, chiar
# daca sistemul ruleaza pe un VM Linux.
#
# `OS` e setata de Windows insusi, deci merge din Git Bash fara nimic in plus.
# Restul comenzilor (test, cp, find, rm) raman POSIX: ruleaza din Git Bash sau
# WSL, nu din cmd.exe.
ifeq ($(OS),Windows_NT)
  BIN    := $(VENV)/Scripts
  PYTHON := python
else
  BIN    := $(VENV)/bin
  PYTHON := python3
endif

PY   := $(BIN)/python
PIP  := $(BIN)/pip

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Creeaza .venv daca lipseste
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)

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
	$(BIN)/triage ingest

poll: ## Ingestie la interval, pana la Ctrl+C
	$(BIN)/triage poll

run: ## Porneste dashboard-ul pe 127.0.0.1:8000
	$(BIN)/uvicorn triage.dashboard.app:app --host 127.0.0.1 --port 8000 --reload

test: ## Ruleaza testele (retea blocata by default)
	$(BIN)/pytest

lint: ## ruff (aceleasi reguli ca in CI)
	$(BIN)/ruff check src tests scripts

fmt: ## formateaza
	$(BIN)/ruff format src tests scripts
	$(BIN)/ruff check --fix src tests scripts

typecheck: ## mypy
	$(BIN)/mypy

ci: lint typecheck test ## tot ce trebuie sa fie verde inainte de PR

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
