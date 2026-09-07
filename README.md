#Phishing Analyzer

# phishing-triage

Sistem local de triaj pentru mailurile de phishing raportate de angajați.
Analiza e complet deterministă (cod Python, nu AI); un LLM local (Ollama)
scrie doar textul de răspuns pe baza verdictului deja decis. Detalii despre
arhitectură în `docs/decisions/`.

## Pornire rapidă (10 minute)

### 1. Cerințe
- Python 3.12+
- [Ollama](https://ollama.com) instalat local, cu un model de 7-8B descărcat
  (vezi `docs/decisions/model-choice.md` pentru care model și de ce)

### 2. Instalare

```bash
git clone <repo>
cd phishing-triage
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt --break-system-packages
```

### 3. Configurare

```bash
cp config/settings.example.yaml config/settings.yaml
cp config/company_domains.example.yaml config/company_domains.yaml
```

Editează `config/company_domains.yaml` cu domeniile reale ale companiei
(`owned_domains`, `mail_infrastructure`, `trusted_partners`,
`company_name_hints`). **Acest fișier nu intră în git.**

### 4. Pornește Ollama

```bash
ollama pull llama3:8b   
ollama serve &
```

### 5. Rulează testele

```bash
pytest
```

Ar trebui să treacă toate (vezi `corpus/README.md` dacă lipsesc fișierele
`.eml` din `corpus/eml/` — 37 de teste depind de ele).

### 6. Procesează un email din linia de comandă

```bash
python -m triage.cli corpus/eml/01_cyberready_forward.eml --json
```

### 7. Pornește dashboard-ul

```bash
uvicorn triage.dashboard.app:app --host 127.0.0.1 --port 8000
```

Deschide `http://127.0.0.1:8000`.

## Arhitectură

Mailbox (IMAP read-only) / Listă .eml statică
→ Fetcher (salvează .eml brut pe disc)
→ Parser (extrage headere, corp, URL-uri, atașamente)
→ Analyzer (verdict determinist + dovezi + scor de încredere)
→ Drafter (Ollama local → text de răspuns RO)
→ Dashboard (FastAPI, doar pe 127.0.0.1)

Cele patru componente din mijloc comunică prin SQLite (`data/db/triage.sqlite3`),
nu direct între ele — un bug în drafter nu blochează ingestia, Ollama picat
nu oprește verdictele.

## Structura proiectului

......
docs/decisions/ - deciziile de arhitectură și de ce au fost luate


## Comenzi utile

| Comandă      | Ce face |
|---|---|
| `pytest` | rulează toate testele |
| `pytest -k "nume_test"` | rulează un test specific |
| `python -m triage.cli fisier.eml --json` | procesează un email izolat |
| `ruff check src/` | linting |
| `mypy src/` | type checking |

## Limitări cunoscute

