# Triaj phishing

Asistent local de triaj pentru mail-urile de phishing raportate de colegi.
Rulează integral pe o mașină din rețeaua internă: nu accesează niciodată
infrastructura atacatorului, nu trimite mail și nu scoate date în afară.

Un coleg raportează un mesaj suspect. Sistemul îl parsează, îi dă un verdict
determinist cu dovezi, scrie o ciornă de răspuns în română, și îl pune într-o
coadă pe care un analist o rezolvă din browser. **Verdictul nu îl dă modelul.**
Modelul doar îmbracă în text dovezile pe care analizorul le-a găsit deja —
și dacă modelul e picat, sistemul funcționează exact la fel, doar cu un
răspuns mai scurt.

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

> **Din experiență**: fiind exclus din git, acest fișier nu are plasă de
> siguranță. O suprascriere din greșeală (de exemplu peste un config de test
> temporar) nu se recuperează cu `git checkout`, pentru că git nu l-a văzut
> niciodată. Înainte de orice experiment care atinge acest fișier —
> generare de date demo, testare cu alt set de domenii, orice —
> `cp config/company_domains.yaml config/company_domains.yaml.backup` întâi,
> ștergi backup-ul după. Un obicei de 5 secunde care evită o oră de
> reconstruit domenii din memorie.

### Corpusul de test

`make corpus` generează 12 cazuri **sintetice**, cu date inventate. Sunt acolo
ca sistemul să aibă pe ce rula pe orice mașină.

Dacă ai corpusul real, copiază-l în `corpus/eml/` (fișierele au aceleași nume),
rulează `./scripts/fix_perms.sh` și sari peste `make corpus`. Diferența contează
— vezi `docs/decisions/0008-corpus-sintetic.md`.

Separat, `corpus/demo/` conține alte câteva mailuri complet fictive — folosite
special pentru capturile din secțiunea „Interfața” de mai jos, ca să poți arăta
cuiva cum arată sistemul fără să expui vreodată o raportare reală, chiar și
neintenționat printr-un screenshot.

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

**Notă de latență**: pe CPU, fără GPU, generarea unei ciorne poate dura
30-90 de secunde — testat direct, nu teoretic. Nu e un bug, e limita
hardware-ului. Dacă timeout-ul din `settings.yaml` e prea strâns, ciorne
valide pică pe fallback fals-negativ; `llm.timeout_seconds: 90` e valoarea
sigură găsită prin măsurare, nu cea implicită de manual.

### Mailbox real (IMAP)

**Nu înainte de discuția cu mentorul** (secțiunea 10). Când e cazul, completezi
credențialele în `.env`, pui `source: imap` în `config/settings.yaml`, și
pornești `make poll`. Conexiunea e read-only: nu șterge, nu mută și nu marchează
nimic.

---

## Interfața

### Coada de lucru
![Coada de lucru](docs/screenshots/queue.png)

Fiecare raportare apare cu verdictul, scorul de încredere afișat ca bară
colorată (roșu sub 60%, portocaliu 60-85%, verde peste), și statusul curent.
Un marker discret arată rândurile pe care un analist le-a corectat sau
escaladat manual, ca să nu se confunde cu verdictul automat.

Filtrele pe verdict și status sunt client-side — clic pe un chip, fără
request nou către server, util când coada are zeci de rapoarte și vrei doar
`MALICIOUS` + `NEW`.

### Detaliu raport

Verdict legitim — o singură dovadă pozitivă, ciornă care confirmă și încurajează raportarea:

![Detaliu raport legitim](docs/screenshots/detail-legitimate.png)

Verdict periculos — cinci dovezi coroborate, colorate pe severitate (roșu = CRITICAL, portocaliu = MEDIUM, verde = LOW):

![Detaliu raport periculos](docs/screenshots/detail-malicious.png)

Dovezile care au dus la verdict sunt colorate pe severitate — nu toate
dovezile cântăresc la fel, și un analist trebuie să vadă instant care
contează. Headerele email-ului sunt dezamorsate, corpul e text curat
(niciodată HTML randat), iar ciorna de răspuns e editabilă direct aici,
cu copiere într-un clic, înainte de trimitere manuală.

### Statistici
![Statistici](docs/screenshots/stats.png)

Distribuția verdictelor și rata de acceptare a ciornelor — dacă analiștii
trimit majoritatea ciornelor neschimbate, drafter-ul își face treaba bine;
dacă rescriu fiecare ciornă, aici se vede exact unde.

**Temă întunecată** disponibilă din butonul din header, salvată local între
sesiuni. Nu e doar cosmetică — un analist care triază rapoarte ore în șir
beneficiază de mai puțină oboseală vizuală decât un fundal alb permanent.

*Capturile de mai sus folosesc exclusiv `corpus/demo/` (vezi mai sus) —
nicio dată reală de companie sau raportare reală nu apare în aceste imagini.*

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

IMAP / corpus -> fetcher -> parser -> analizor -> drafter -> SQLite
|
dashboard <--+


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

**qwen2.5:7b-instruct**, ales în urma unei evaluări comparative cu
`llama3.1:8b` — motivul complet, cu cifre, e în
[`docs/decisions/0004-modelul-pentru-drafter.md`](docs/decisions/0004-modelul-pentru-drafter.md).

Pe scurt: `qwen2.5:7b-instruct` nu a dezvăluit niciodată natura de
simulare pe categoria `SIMULATION` (criteriul de siguranță cel mai
important), deși ambele modele aveau eșecuri pe alte constrângeri de
formă. Latența (30-90s pe CPU, fără GPU) rămâne peste bugetul țintă de
30s din criteriul de acceptanță — vezi decizia pentru detalii.

Pentru a re-evalua pe alt hardware sau alt model:

```bash
python3 scripts/eval_model.py --baseline
python3 scripts/eval_model.py --models qwen2.5:7b-instruct,llama3.1:8b --runs 5 --out build/eval.md
```

## Probleme întâlnite frecvent

O listă scurtă de simptome pe care le-am văzut concret în timpul dezvoltării,
ca să nu mai piardă nimeni timp reinventând diagnosticul.

**`ImportError: cannot import name '...' from partially initialized module`**
la pornirea dashboard-ului sau la orice import din `triage.settings` —
import circular. `triage/settings.py` și `triage/drafter` se importă reciproc
dacă clientul Ollama e importat la nivel de modul în settings. Fix: import-ul
respectiv stă sub `if TYPE_CHECKING:`, cu importul real local, în interiorul
funcției care chiar are nevoie de el la runtime.

**`yaml.scanner.ScannerError` la pornirea testelor, doar în CI, niciodată local**
— aproape sigur config-ul `.example.yaml` are o eroare de sintaxă pe care
n-o vezi niciodată local, pentru că mereu ai fișierul real (exclus din git)
și fallback-ul pe `.example` nu se declanșează la tine. Testează local
simulând absența fișierului real (`mv` temporar) înainte să presupui că
CI-ul e stricat.

**Teste care depind de `corpus/eml/` pică cu `IndexError`/`AssertionError`
în loc să se sară** — lipsește marker-ul de skip pe acel test specific.
Verifică dacă fișierul de test importă corect markerul comun de
„sari dacă lipsește corpusul” (definit o singură dată, nu duplicat).

**Text invizibil în tema întunecată** — aproape sigur un `style="color: #hex"`
inline, hardcodat direct în HTML, care ignoră variabilele CSS de temă.
Regula de bază pentru orice interfață nouă: nicio culoare hardcodată inline
în șabloane, totul prin variabile CSS din `app.css`.

---

## Dezvoltare

```bash
make ci          # ruff + mypy + pytest, tot ce trebuie verde înainte de PR
make test        # doar testele
make status      # panou de progres -> build/status.html
```

Branch per funcționalitate, PR către `main`, review înainte de merge — nu
direct pe `main`. Mesajele de commit descriu **ce** s-a schimbat și **de ce**,
nu doar „fix” sau „update” — peste o lună, `git log` e primul loc unde cauți
când ceva s-a stricat, și trebuie să te ajute, nu doar să confirme că ceva
s-a întâmplat.

Deciziile de arhitectură sunt în `docs/decisions/`. Fiecare spune ce s-a decis,
de ce, și ce s-a dat la schimb.

Datele sensibile care nu intră niciodată în git: `data/`, `.env`,
`config/settings.yaml`, `config/company_domains.yaml`, `corpus/eml/`,
`corpus/msg/`.
