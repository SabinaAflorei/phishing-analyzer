# Triaj phishing

Asistent local de triaj pentru mail-urile de phishing raportate de colegi.
Rulează integral pe o mașină din rețeaua internă: nu accesează niciodată
infrastructura atacatorului, nu trimite mail și nu scoate date în afară.

Un coleg raportează un mesaj suspect. Sistemul îl parsează, îi dă un verdict
determinist cu dovezi, scrie o ciornă de răspuns în română, și îl pune într-o
coadă pe care un analist o rezolvă din browser. **Verdictul nu îl dă modelul.**
Modelul doar îmbracă în text dovezile pe care analizorul le-a găsit deja.

---

## Pornire

Ai nevoie doar de **Python 3.12 sau mai nou**. Ollama e opțional — fără el
sistemul folosește șabloanele statice și merge la fel.

```bash
git clone https://github.com/czky/phishing-analyzer.git
cd phishing-analyzer

make setup      # creează .venv, instalează tot, copiază fișierele de configurare
make corpus     # 12 cazuri sintetice de test — sari peste dacă ai corpusul real
make ingest     # procesează corpusul și umple coada
make run        # dashboard pe http://127.0.0.1:8000
```

Patru comenzi. Deschide `http://127.0.0.1:8000` — ar trebui să vezi 12 raportări
cu verdicte. Oprești serverul cu `Ctrl+C`.

Dacă vrei să verifici că totul e în regulă înainte:

```bash
make test       # 359 de teste, rețeaua blocată
```

### Ce face `make setup`

Creează `.venv`, instalează dependințele și pachetul, apoi copiază cele trei
fișiere de configurare din variantele `.example`:

| Fișier | La ce e | Trebuie editat? |
|---|---|---|
| `config/settings.yaml` | sursă, căi, LLM, dashboard | nu, merge așa |
| `config/company_domains.yaml` | domeniile companiei, partenerii de încredere | **da**, vezi mai jos |
| `.env` | doar credențiale IMAP | nu încă — vezi „Mailbox real” |

Niciunul nu intră în git.

### Singurul fișier pe care chiar trebuie să îl editezi

`config/company_domains.yaml` — pune acolo domeniile reale ale companiei,
hostname-urile serverelor de mail și adresa la care raportează angajații. De
ele depind patru reguli: spoofing de domeniu intern, lookalike, TLD cu risc
ridicat, și recunoașterea învelișului de raportare.

Dacă îl lași necompletat sistemul pornește oricum, cade pe varianta `.example`
și scrie un avertisment în log — ca să nu descoperi peste două săptămâni că
jumătate din reguli mergeau pe date de exemplu.

### Corpusul de test

`make corpus` generează 12 cazuri **sintetice**, cu date inventate. Sunt acolo
ca sistemul să aibă pe ce rula pe orice mașină.

Dacă ai corpusul real, copiază-l în `corpus/eml/` (fișierele au aceleași nume),
rulează `./scripts/fix_perms.sh` și sari peste `make corpus`. Diferența contează
— vezi `docs/decisions/0008-corpus-sintetic.md`.

### Ollama, dacă îl vrei

Nu e nevoie de el ca să pornești. Fără Ollama, ciornele vin din șabloanele
statice, iar la ingestie apare o singură linie de log care spune asta.

```bash
ollama pull qwen2.5:7b-instruct
python3 scripts/eval_model.py --models qwen2.5:7b-instruct,llama3.1:8b --runs 3
```

Scriptul rulează aceleași cazuri de N ori și verifică automat structura,
diacriticele, lungimea și constrângerile per categorie. Modelul ales se pune în
`config/settings.yaml`, la `llm.model`. Ca să oprești complet LLM-ul:
`llm.enabled: false`.

### Mailbox real (IMAP)

**Nu înainte de discuția cu mentorul** (secțiunea 10). Când e cazul, completezi
credențialele în `.env`, pui `source: imap` în `config/settings.yaml`, și
pornești `make poll`. Conexiunea e read-only: nu șterge, nu mută și nu marchează
nimic.

---

## Ce face fiecare comandă

Din `make`:

| Comandă | Ce face |
|---|---|
| `make setup` | venv + dependințe + fișiere de configurare |
| `make corpus` | generează corpusul sintetic de test |
| `make ingest` | un ciclu de ingestie din sursa configurată |
| `make poll` | ingestie la interval, până la `Ctrl+C` |
| `make run` | dashboard pe `127.0.0.1:8000` |
| `make test` | testele, cu rețeaua blocată |
| `make ci` | ruff + mypy + teste — tot ce trebuie verde înainte de PR |
| `make status` | panou de progres → `build/status.html` |
| `make clean` | șterge cache-urile și `build/` |

Direct din CLI (după `make setup`, binarul e în `.venv/bin/triage`):

```bash
triage ingest                 # un ciclu de ingestie
triage poll --interval 300    # ingestie la interval
triage list --status NEW      # ce e în coadă
triage list --verdict SPAM    # filtrat pe verdict
triage show 3                 # un raport, cu dovezi și ciornă
triage check mail.eml         # analizează un .eml fără să îl salveze nicăieri
triage check mail.eml --json  # același lucru, pentru scripting
```

`check` e singura comandă care nu atinge baza de date. Toate acceptă `--json`
unde are sens, și `-v` pentru log detaliat.

---

## Cum e făcut

Patru componente independente care comunică printr-o bază de date SQLite.
Niciuna nu o cheamă direct pe următoarea.

```
IMAP / corpus  ->  fetcher  ->  parser  ->  analizor  ->  drafter  ->  SQLite
                                                                        |
                                                          dashboard  <--+
```

De aici vin trei proprietăți pe care se sprijină tot restul:

- **Ollama picat**: verdictele se produc oricum, ciorna vine din șablonul static.
- **Dashboard oprit**: ingestia continuă, scrie în baza de date.
- **Bug în drafter**: excepția e prinsă pentru mailul respectiv, raportul se
  salvează fără ciornă, restul cozii trece mai departe.

| Modul | Ce face |
|---|---|
| `triage/fetcher` | IMAP read-only și sursa offline de `.eml`. Nu șterge, nu mută, nu marchează. |
| `triage/parser` | Scoate mesajul **original**, nu învelișul colegului care a raportat. |
| `triage/analyzer` | Verdictul determinist. Fără AI. Fiecare semnal produce o dovadă. |
| `triage/drafter` | Ciorna în română. Ollama dacă răspunde, șablon static altfel. |
| `triage/db` | Tabelul `reports`. Singurul loc prin care componentele se văd. |
| `triage/pipeline` | Drumul complet, folosit de CLI, de dashboard și de poll. |
| `triage/dashboard` | Coada, detaliul, statisticile. |

### Verdictul e o funcție de dovezi

Toate regulile rulează, niciuna nu iese devreme, iar dovezile se adună.
Ponderile stau într-un singur tabel, `SIGNAL_WEIGHT` din `triage/analyzer`, și
două praguri decid:

- **1.0** e suficient singur pentru `MALICIOUS`: eșec de autentificare,
  atașament periculos, spoofing de domeniu propriu.
- Sub 1.0, un semnal are nevoie de coroborare. Trei semnale medii —
  Reply-To nepotrivit, urgență artificială, cerere de credențiale — ajung
  împreună la un verdict pe care niciunul nu îl justifică singur.
- Între 0.4 și 1.0 iese `NEEDS_REVIEW`, cu dovada că semnalele s-au coroborat
  fără să atingă pragul. Decide un analist.

Regula pe care o respectă tot fișierul: severitatea unei dovezi și greutatea ei
merg împreună. Dacă scrii `Severity.MEDIUM`, nu poți obține `MALICIOUS` dintr-un
singur semnal.

---

## Securitate

Ce **nu** face sistemul, prin construcție:

- Nu accesează niciun URL raportat, nu rezolvă DNS pe el, nu descarcă nimic.
  Testele rulează cu socket-urile blocate: dacă cineva adaugă un `httpx.get`
  pe un domeniu raportat, suita cade.
- Nu deschide atașamentele. Verdictul vine din metadate: nume, extensie,
  dimensiune, SHA256, și flagul de criptare din headerul ZIP.
- Nu randează HTML din mail. Dashboard-ul arată doar text, deja dezamorsat.
- Nu trimite mail. Ciorna se copiază manual de analist.
- Ascultă doar pe `127.0.0.1`. `config/settings.yaml` respinge orice altceva
  la pornire, la fel și un `llm.base_url` care nu e pe loopback.

Ce iese din sistem e **dezamorsat**: `hxxps[://]exemplu[.]com`. Asta e valabil
și în baza de date, care e locul cel mai ușor de uitat.

Textul care ajunge la model e curățat înainte: tag-uri `script`/`style`,
elemente ascunse prin stil (`display:none`, 1px, alb pe alb), caractere Unicode
invizibile, și trunchiere la `llm.max_input_chars`. Output-ul modelului e
validat structural; dacă nu are salut, corp și încheiere, e aruncat și se
folosește șablonul.

### Înainte de prima ingestie reală

- [ ] Snapshot al VM-ului. Se face o dată și se uită ușor.
- [ ] Verifică `scripts/check_bind_localhost.sh` — nimic expus în afara loopback.
- [ ] `data/` e exclus din backup-urile automate. Directorul are un
      `CACHEDIR.TAG`, pe care borg, restic și `tar --exclude-caches` îl
      respectă. Dacă folosești altceva, exclude-l explicit.
- [ ] Discută cu mentorul înainte să conectezi mailbox-ul real (secțiunea 10).

---

## Corpusul de test

`corpus/eml/` conține raportări reale — nume și adrese de colegi, contacte
externe, URL-uri de tracking cu token per destinatar. **Nu intră în git** și se
copiază pe VM prin alt canal.

Pe o mașină fără el, `scripts/make_synthetic_corpus.py` generează 12 înlocuitori
cu aceeași structură MIME și aceleași semnale, dar cu date inventate. Un test
care trece pe corpusul sintetic arată că pipeline-ul funcționează pe forma pe
care o aștept eu de la mailuri — nu că funcționează pe mailurile care chiar vin.
Când primești corpusul real, îl copiezi peste (aceleași nume) și rulezi din nou.

`corpus/expected/*.yaml` intră în git: sunt doar verdictul așteptat și codurile
de dovezi obligatorii, fără conținut sensibil.

---

## Modelul ales

**Încă nemăsurat pe această mașină** — Ollama nu e instalat aici, deci
`scripts/eval_model.py` nu a putut rula pe niciun model. `llama3.1:8b` din
`settings.example.yaml` este un punct de pornire moștenit, **nu o decizie**.

Ce trebuie făcut, pe VM-ul cu Ollama:

```bash
python3 scripts/eval_model.py --baseline    # reperul: șabloanele scrise de om
python3 scripts/eval_model.py --models qwen2.5:7b-instruct,llama3.1:8b,mistral-nemo:12b \
        --runs 5 --out build/eval.md
```

Apoi completează aici tabelul din `build/eval.md` și scrie în
`docs/decisions/0004-modelul-pentru-drafter.md` de ce ai ales ce ai ales.
Criteriul de oprire e în script: peste 30s la cald înseamnă că modelul nu
încape în bugetul din 8.1.

---

## Dezvoltare

```bash
make ci          # ruff + mypy + pytest, tot ce trebuie verde înainte de PR
make test        # doar testele
make status      # panou de progres -> build/status.html
```

Deciziile de arhitectură sunt în `docs/decisions/`. Fiecare spune ce s-a decis,
de ce, și ce s-a dat la schimb.

Datele sensibile care nu intră niciodată în git: `data/`, `.env`,
`config/settings.yaml`, `config/company_domains.yaml`, `corpus/eml/`,
`corpus/msg/`.
