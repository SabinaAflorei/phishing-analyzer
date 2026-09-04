# Triaj phishing

Asistent local de triaj pentru mail-urile de phishing raportate de colegi.
Rulează integral pe o mașină din rețeaua internă: nu accesează niciodată
infrastructura atacatorului, nu trimite mail și nu scoate date în afară.

Un coleg raportează un mesaj suspect. Sistemul îl parsează, îi dă un verdict
determinist cu dovezi, scrie o ciornă de răspuns în română, și îl pune într-o
coadă pe care un analist o rezolvă din browser. **Verdictul nu îl dă modelul.**
Modelul doar îmbracă în text dovezile pe care analizorul le-a găsit deja.

---

## Pornire în 10 minute

Ai nevoie de Python 3.12 sau mai nou. Ollama e opțional — fără el, sistemul
folosește șabloanele statice și merge la fel.

```bash
git clone <repo> && cd phishing-analyzer

python3 -m venv .venv
make install                  # dependințe + pachetul, editabil

cp config/settings.example.yaml config/settings.yaml
cp config/company_domains.example.yaml config/company_domains.yaml
cp .env.example .env          # doar credențiale IMAP; lasă-le goale deocamdată
```

Editează `config/company_domains.yaml` cu domeniile reale ale companiei.
Fișierul nu intră în git — conține numele serverelor interne. Dacă îl uiți,
sistemul cade pe varianta `.example` și scrie un avertisment în log, ca să nu
descoperi peste două săptămâni că jumătate din reguli erau inerte.

Îți trebuie corpus de test. Dacă nu ai încă cel real:

```bash
python3 scripts/make_synthetic_corpus.py    # 12 cazuri sintetice în corpus/eml/
```

Apoi:

```bash
make test                     # 337 de teste, rețeaua blocată
.venv/bin/triage ingest       # umple coada din corpus
make run                      # dashboard pe http://127.0.0.1:8000
```

Deschide `http://127.0.0.1:8000`. Ar trebui să vezi 12 raportări cu verdicte.

### Ollama, dacă îl vrei

```bash
ollama pull qwen2.5:7b-instruct
python3 scripts/eval_model.py --models qwen2.5:7b-instruct,llama3.1:8b --runs 3
```

Scriptul rulează aceleași cazuri de N ori și verifică automat structura,
diacriticele, lungimea și constrângerile per categorie. **Rezultatele se scriu
mai jos, la „Modelul ales”.** Modelul se pune în `config/settings.yaml`, la
`llm.model`. Ca să oprești complet LLM-ul: `llm.enabled: false`.

---

## Ce face fiecare comandă

```bash
triage ingest                 # un ciclu de ingestie din sursa configurată
triage poll --interval 300    # ingestie la interval, până la Ctrl+C
triage list --status NEW      # ce e în coadă
triage show 3                 # un raport, cu dovezi și ciornă
triage check mail.eml         # analizează un .eml fără să îl salveze nicăieri
```

`check` e singura comandă care nu atinge baza de date.

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
