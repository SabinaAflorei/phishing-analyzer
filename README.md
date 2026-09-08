#Phishing Analyzer

# phishing-triage

Sistem local de triaj pentru mailurile de phishing raportate de angajați.
Analiza e complet deterministă (cod Python, nu AI); un LLM local (Ollama)
scrie doar textul de răspuns pe baza verdictului deja decis — verdictul
nu poate fi schimbat de model. Detalii despre deciziile de arhitectură în
[`docs/decisions/`].
## Pornire rapidă

### 1. Cerințe

- Python 3.12+
- [Ollama](https://ollama.com) instalat local

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

Editezi `config/company_domains.yaml` cu domeniile reale ale companiei
(`owned_domains`, `mail_infrastructure`, `trusted_partners`,
`company_name_hints`). **Acest fișier nu intră în git** — conține nume de
infrastructură internă.

### 4. Pornești Ollama

```bash
ollama pull qwen2.5:7b-instruct
ollama serve
```

Modelul a fost ales pe baza unei evaluări comparative (rată de corectitudine
în română, siguranță pe categoria SIMULATION, latență) — detalii complete în
[`docs/decisions/model-choice.md`].

**Notă pe latență:** pe hardware fără GPU, generarea unui draft poate dura
30-90 de secunde. `config/settings.yaml` are `llm.timeout_seconds: 90` ca
să nu piardă drafturi valide pe un timeout prea strâns. Verdictul determinist
rămâne instant — doar drafturile scrise de LLM sunt lente.

### 5. Aduci corpusul de test (opțional, dar recomandat)

Vezi [`corpus/README.md`](corpus/README.md) — fișierele `.eml` nu intră
în git. Fără ele, testele care depind de corpus se sar automat, cu mesaj
explicit.

### 6. Rulezi testele

```bash
pytest
```

### 7. Procesezi un email din linia de comandă

```bash
python -m triage.cli corpus/eml/01_cyberready_forward.eml --json
```

### 8. Ingerezi tot corpusul în baza de date

```bash
python -c "from pathlib import Path; from triage.ingest import ingest_corpus; print(ingest_corpus(Path('corpus/eml')))"
```

### 9. Pornești dashboard-ul

```bash
uvicorn triage.dashboard.app:app --host 127.0.0.1 --port 8000
```

Deschizi `http://127.0.0.1:8000`. Ascultă doar pe localhost — niciodată pe
`0.0.0.0`.

## Arhitectură

Mailbox (IMAP read-only) / Listă .eml statică
→ Fetcher (salvează .eml brut, idempotent prin hash de conținut, retry cu backoff)
→ Parser (extrage headere, corp text/HTML separat, URL-uri, atașamente)
→ Analyzer (verdict determinist, scor ponderat pe severitate + dovezi)
→ Drafter (Ollama local → text RO; fallback pe template static)
→ Dashboard (FastAPI, doar pe 127.0.0.1)


Cele patru componente din mijloc comunică prin SQLite
(`data/db/triage.sqlite3`), nu direct între ele — dacă Ollama e picat,
verdictele se produc oricum. Dacă dashboard-ul e oprit, ingestia continuă.
Un bug în drafter nu pierde niciodată un mail.

**Principiu central:** verdictul e decis de cod Python obișnuit, testabil,
auditabil. LLM-ul primește verdictul deja stabilit și dovezile, și scrie
doar formularea — nu poate schimba decizia. Motivul complet în
[`docs/decisions/deterministic-verdict.md`].

## Structura proiectului

src/triage/
fetcher/ - citire .eml din corpus sau IMAP (cu retry)
parser/ - extragere headere/corp/URL-uri/atașamente/homoglife
analyzer/ - verdict determinist (scor de dovezi coroborate)
drafter/ - generare draft (Ollama + fallback static)
dashboard/ - FastAPI: coadă, detaliu, statistici
db.py - persistență SQLite
html_hygiene.py - detecție text ascuns prin stil CSS
settings.py - config centralizat (pydantic-settings)
config/ - YAML: domenii companie, fingerprint CyberReady, reguli atașamente
corpus/ - 12 cazuri de test (.eml + verdict + dovezi așteptate)
docs/decisions/ - deciziile de arhitectură și motivarea lor
tests/ - suite pytest, inclusiv teste de securitate (rețea blocată, etc.)


## Comenzi utile

| Comandă | Ce face |
|---|---|
| `pytest` | rulează toate testele |
| `pytest -k "nume"` | rulează un test specific |
| `pytest --cov=src/triage --cov-report=term-missing` | coverage detaliat |
| `python -m triage.cli fisier.eml --json` | procesează un email izolat |
| `ruff check src tests scripts` | linting |
| `mypy` | type checking |

## Categorii de verdict

| Verdict | Când | Draft generat? |
|---|---|---|
| `SIMULATION` | Fingerprint CyberReady confirmat | Da, ton neutru |
| `MALICIOUS` | Semnale clare de phishing/malware | Da, cere ștergerea |
| `SPAM` | Marketing nesolicitat, fără risc | Da, liniștește |
| `LEGITIMATE` | Email real, doar cu încredere mare | Da, confirmă și încurajează raportarea |
| `NEEDS_REVIEW` | Semnale insuficiente sau contradictorii | **Nu** — analistul decide manual |

## Limitări cunoscute

- IMAP e implementat (conectare cu retry, idempotență) dar **nu conectat
  la mailbox real** — necesită discuție explicită cu echipa înainte.
- Modulul de îmbogățire externă (reputație URL, vârstă domeniu) e oprit
  implicit (`enrichment.enabled: false`), offline-first.
- Latența drafter-ului (30-90s) depășește bugetul țintă de 30s din
  criteriul de acceptanță 8.1 — vezi `docs/decisions/model-choice.md`.
- Rata de corectitudine automată a drafturilor generate de LLM e sub
  target (25-42% pe eșantion mic) — draftul rămâne întotdeauna editabil
  de analist înainte de trimitere, niciodată trimis automat.