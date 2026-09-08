# TODO - ce a mai ramas din foaia de task

Lista e organizata pe sectiunile din foaia de task, ca sa poti bifa direct.

Legenda: `[x]` gata &nbsp; `[~]` partial, mai are nevoie de lucru &nbsp; `[ ]` nefacut

**Bug-urile din codul existent NU sunt in lista asta.** Sunt marcate direct in
cod, langa linia care are problema. Le vezi cu:

```
grep -rn "TODO(" src/ config/ tests/ .github/
```

Fa-le pe alea intai unde sunt marcate `prioritate maxima` - sunt lucruri care
dau verdict gresit acum, si nu are sens sa construiesti peste ele.

---

## Unde esti acum

Merge deja: parser-ul pe cele trei forme de raportare, analizorul determinist cu
verdict + dovezi + scor, template-urile statice pe cele 5 categorii, defanging-ul,
dashboard-ul cu coada / detaliu / statistici, CLI-ul, si testele de securitate
(retea blocata, permisiuni, bind pe localhost).

Golul cel mai mare, ca sa il stii de la inceput: **nu exista baza de date, si
LLM-ul nu e conectat**. Adica doua din cele sase componente din sectiunea 3 nu
sunt inca acolo, iar fara baza de date componentele nu comunica intre ele asa cum
cere arhitectura.

---

## A. Arhitectura (sectiunea 3)

### [x] A1. Baza de date - nu exista deloc

**Ce cere foaia:** cele patru componente (fetcher, parser, analyzer, drafter)
sunt independente si comunica printr-o baza de date. "Daca Ollama e picat,
verdictele se produc oricum. Daca dashboard e oprit, ingestia continua. Un bug in
drafter nu pierde niciodata un mail."

**Ce e acum:** nimic nu se persista. `load_real_reports()` din
`src/triage/dashboard/app.py` reparseaza tot corpusul, de la zero, la fiecare
cerere HTTP. `sqlalchemy` si `alembic` sunt in `requirements.txt` dar nu le
foloseste nimeni, iar `config/settings.example.yaml` pomeneste un
`db_path: data/db/triage.sqlite3` care nu e citit de nicaieri.

**De ce conteaza:** fara ea, componentele nu sunt independente - sunt un singur
lant care ruleaza in intregime la fiecare refresh. Si consecintele se vad deja in
dashboard, vezi G1 si G2.

**Cum incepi:** tabel `reports` cu ce ai deja in dictionarul construit de
`load_real_reports()` (id, data, raportor, subiect, verdict, incredere, dovezi,
draft, status) plus hash-ul fisierului .eml ca sa nu duplici la repornire.
SQLite cu SQLAlchemy, ca sunt deja in requirements. Alembic il pui cand ai prima
schimbare de schema, nu de la inceput.

### [x] A2. `config/settings.yaml` nu e citit de niciun modul

**Ce e acum:** fisierul exemplu exista si e bine scris, dar niciun modul nu il
incarca. `poll_interval_seconds`, `llm.*`, `enrichment.enabled`, `paths.*`,
`dashboard.host/port` sunt toate inerte. `pydantic-settings` e in requirements
si nefolosit.

**De ce conteaza:** foaia cere ca imbogatirea externa "sa se poata dezactiva
explicit" (sectiunea Configurare). Momentan nu exista comutatorul.

**Cum rezolvi:** un modul `settings.py` cu `BaseSettings` din pydantic-settings,
incarcat o singura data la pornire si pasat mai departe. Cu fallback pe
`.example` daca fisierul real lipseste - aceeasi problema ca la
`company_domains.yaml`, vezi TODO-ul din analyzer.

---

## B. Fetcher (sectiunea 6.1)

### [~] B1. IMAP e stub

`src/triage/fetcher/__init__.py` are `fetch_from_corpus()` functional, dar
`fetch_from_imap()` doar scrie in log si intoarce lista goala.

Ce mai lipseste din 6.1:
- [ ] Conectare IMAP read-only cu app password (din `.env`, nu din cod)
- [ ] Poll la interval configurabil, default 5 minute (vine din A2)
- [ ] Marcarea mesajelor procesate prin flag IMAP sau evidenta in DB, **fara sa
      le stearga** (depinde de A1)
- [ ] Repornirea nu reproceseaza si nu dublica (idempotenta - foloseste hash-ul
      .eml sau Message-ID)
- [ ] Retry la mailbox indisponibil, fara pierdere de mesaje (criteriu 8.3)

**Atentie:** nu conecta la mailbox-ul real inainte sa discuti cu mentorul -
e scris explicit in sectiunea 10. Pana atunci testeaza cu un server IMAP local
sau cu un mock.

---

## C. Parser (sectiunea 6.2)

Cele trei forme de raportare sunt detectate, iar extragerea mesajului original
merge pentru atasament. Ce lipseste din lista de campuri ceruta:

- [x] **Display-name-ul expeditorului**, separat de adresa. E nevoie de el pentru
      semnalul "nepotrivire intre display-name si domeniul real" (vezi D4).
      `email.utils.parseaddr` iti da deja ambele, dar acum se pastreaza doar adresa.
- [x] **Corpul HTML**, pastrat separat de cel text. Foaia zice explicit: HTML
      "doar pentru extragere URL-uri, niciodata pentru afisare". Acum HTML-ul se
      arunca aproape mereu - vezi TODO-ul de la `if not body_text_parts` din parser.
- [x] **Textul ancorei impreuna cu href-ul**, ca perechi. Fara ele nu poti face
      semnalul de discrepanta text-link din 6.3. Acum se retin doar href-urile.
- [x] **Arhive protejate cu parola** - detectabile din metadate (flag-ul de
      criptare din headerul ZIP), fara sa deschizi arhiva. Cerut la 6.3.

---

## D. Analizor determinist (sectiunea 6.3)

Ai deja: SPF/DKIM/DMARC, fingerprint CyberReady, extensii de atasament, dubla
extensie, lookalike pe Levenshtein, TLD cu risc ridicat, spoofing de domeniu intern.

Semnale din foaie care lipsesc complet:

- [x] **D1. Reply-To diferit de From.** Campul `reply_to` se parseaza deja si se
      pune in `ParsedEmail`, dar analizorul nu il citeste niciodata. E semnalul cel
      mai ieftin de adaugat din toata lista.
- [x] **D2. Return-Path care nu corespunde cu From.** Idem, campul exista si e
      neatins.
- [x] **D3. Homoglife si punycode / IDN.** `confusable-homoglyphs` e in
      `requirements.txt` si nu il foloseste nimeni. Un domeniu `xn--`, sau unul cu
      un chirilic "а" in loc de "a" latin, trece acum complet nedetectat -
      Levenshtein nu il prinde, pentru ca distanta e 0 la nivel de aspect si mare
      la nivel de bytes.
- [x] **D4. Nepotrivire intre display-name si domeniul real.** Clasicul
      `From: "Banca X" <atacator@rau.tld>`. Depinde de C1.
- [x] **D5. Semnale de continut** (pondere mica, dar coroborante, zice foaia):
      urgenta artificiala, cereri de credentiale, discrepanta intre textul
      link-ului si href. Ultimul depinde de C3.
- [] **D6. Coroborarea semnalelor.** Acum fiecare regula face `return` imediat ce
      se potriveste, deci se opreste la prima. Foaia cere ca verdictul sa fie "o
      functie de dovezi" si ca semnalele de continut sa aiba "pondere mica, dar
      coroboranta" - ceea ce presupune sa le aduni, nu sa iesi la prima.
      Refactorizarea asta o faci dupa ce rezolvi bug-urile marcate in cod, altfel
      muti bug-urile in structura noua. E cea mai mare bucata de lucru din
      sectiunea D.

---

## E. Drafter (sectiunea 6.4)

### [x] E1. Ollama nu e conectat - LLM-ul nu ruleaza niciodata

**Ce e acum:** `build_draft()` are parametrul `llm_client: Any = None`, si
`if llm_client is not None:` inconjoara toata logica de generare. Nimeni, in tot
proiectul, nu pasa vreodata un `llm_client`. Nici CLI-ul, nici dashboard-ul.
Adica: se foloseste **intotdeauna** template-ul static.

Nu e o critica a fallback-ului - fallback-ul e scris corect si e obligatoriu prin
foaie. Doar ca acum e singura cale.

**Cum rezolvi:** un client mic peste `http://127.0.0.1:11434`, cu o metoda
`generate(system_prompt, prompt, temperature)`, ca aia e semnatura pe care
`build_draft` o asteapta deja. Ai un exemplu de vorbit cu Ollama, doar din
stdlib, in `scripts/eval_model.py` - foloseste-l ca model. Config-ul (base_url,
model, temperatura, timeout) vine din A2.

- [x] E2. Timeout pe apelul catre Ollama, ca sa nu blocheze pipeline-ul.
      `timeout_seconds: 30` exista deja in settings, trebuie doar folosit.
- [ ] E3. Trunchiere la `max_input_chars` (2000) inainte de model - sectiunea 4.4
      punctul 2. `sanitize_for_model` are deja `max_chars=2000` ca default, dar
      valoarea trebuie sa vina din config, nu din semnatura functiei.
- [ ] E4. Ruleaza `scripts/eval_model.py` pe cateva modele si **scrie rezultatul
      in README**. Foaia cere explicit sa testezi limba romana si zice ca
      `llama3.1:8b` e "punct de pornire, NU o decizie". Scriptul e deja scris si
      verifica diacritice, structura si lungime - trebuie doar rulat si decis.
- [ ] E5. Test care demonstreaza fallback-ul: cu Ollama picat, sistemul continua
      si scoate template static (criteriu 8.3).

---

## F. Dashboard (sectiunea 6.5)

### [x] F1. Butoanele "Marcheaza trimis" si "Escaleaza" nu fac nimic

`detail.html` trimite `value="mark_sent"` si `value="escalate"`, dar
`handle_report_action()` din `app.py` trateaza doar `save_draft` si
`override_verdict`. Celelalte doua cad pe ramura de else inexistenta: se
raspunde cu "Actiune inregistrata cu succes", dar nu se salveaza nimic.
Mesajul de succes e mai rau decat o eroare - ascunde problema.

### [x] F2. Statusul si corectiile de verdict nu se pastreaza

- In `load_real_reports()`, `"status": "NEW"` e hardcodat la fiecare incarcare.
- `handle_bulk_action()` schimba `report["status"]` pe o lista reconstruita la
  cererea curenta - se pierde imediat ce se trimite raspunsul.
- `save_verdict_override()` chiar scrie in `data/feedback.json`, dar
  `load_real_reports()` nu citeste niciodata inapoi override-urile.

Deci: filtrele pe status din `queue.html` exista in interfata, dar nu au ce
filtra, iar o corectie de verdict dispare la refresh. Toate trei se rezolva
odata cu A1.

### [ ] F3. Pagina de statistici - completeaza metricile

`get_feedback_stats()` da rata de acceptare si numarul de corectii. Foaia cere in
plus: **distributia de verdicte** si **corectiile pe categorii** (care verdict e
cel mai des corectat, si in ce e schimbat). Aia e informatia care iti spune unde
sa te uiti, si e "principala metrica de calitate" dupa foaie.

---

## G. Securitate (sectiunea 4)

Partea grea e facuta si testata: retea blocata in teste, defanging, bind pe
127.0.0.1, permisiuni 600, escapare Jinja2. Ce a ramas:

- [ ] **G1. Testul de prompt injection e `xfail`.**
      `tests/test_prompt_injection.py` e inca `raise NotImplementedError` sub
      `@pytest.mark.xfail`. E criteriu de acceptanta la 8.2 si test obligatoriu la
      4.4 punctul 4. Vezi si TODO-ul din analyzer - regula actuala face exact
      invers decat cere cazul 08, deci intai repari regula, apoi scrii testul.
- [ ] **G2. Curatarea textului ascuns inainte de model** (4.4 punctul 1).
      `sanitize_for_model` scoate deja tag-uri script/style si caractere
      invizibile. Mai lipseste: text cu culoare identica cu fundalul (alb pe alb)
      si `font-size:1px`. Alea sunt in atributele de stil, deci ai nevoie de
      HTML-ul pastrat separat - vezi C2.
- [ ] **G3. Validarea output-ului de la model** (4.4 punctul 3) - `split_email`
      face verificarea si exista fallback-ul. Se poate bifa dupa ce E1 e gata si
      chiar trece cineva prin ramura aia. Pana atunci nu e testat pe bune.
- [ ] **G4. Snapshot al VM-ului inainte de prima ingestie reala** (4.5). Nu e cod,
      dar e pe lista si se uita usor.
- [ ] **G5. Directorul cu .eml brute exclus din backup-uri automate** (4.5).
- [ ] **G6. Modulul de imbogatire** (optional prin foaie, dar daca il faci):
      submisie privata implicit si curatarea token-ului per-destinatar din URL
      inainte de trimitere (4.6). Comutatorul e deja prevazut in settings.

---

## H. Corpus de test (sectiunea 7)

- [x] **H1. Fisierele `.eml` lipsesc de pe masina asta.** Exista toate cele 12
      `corpus/expected/*.yaml`, dar `corpus/eml/` e gol, deci **37 de teste se sar**
      la fiecare rulare. Copiaza corpusul pe VM prin canalul discutat (vezi
      `corpus/README.md`). Fara el nu poti valida niciun criteriu functional din 8.1.
- [ ] **H2. Cazul 12 nu e in foaie.** Foaia listeaza 11 cazuri, repo-ul are 12
      (`12_stripped_attachment_quote`). Daca l-ai adaugat tu, bine - dar spune la
      stand-up si scrie in `notes:` de ce exista, altfel peste doua luni nimeni nu
      mai stie daca e intentionat sau ramasita.
- [ ] **H3. `must_contain_evidence` e gol peste tot.** Toate cele 12 yaml-uri au
      `must_contain_evidence: []`. Comentariul din ele zice sa le completezi "pe
      masura ce definesti vocabularul de semnale". Vocabularul exista deja
      (`AUTH_FAILURE`, `CYBEREADY_SIMULATION`, `SUSPECT_ATTACHMENT`, ...), deci
      se pot completa acum.

---

## I. Criterii de acceptanta (sectiunea 8)

### Functionale (8.1)
- [ ] I1. Toate cele 11 cazuri primesc verdict corect - **neverificabil acum**,
      lipsesc si corpusul (H1) si testul care compara (vezi TODO din
      `tests/test_corpus.py`).
- [ ] I2. Precizie 100% pe detectia CyberReady - vezi TODO-urile din analyzer si
      `cyberready.yaml`; acum sunt doua cai prin care iese SIMULATION gresit.
- [ ] I3. Sub 30 de secunde de la ingestie la draft - nemasurat. Se masoara serios
      abia dupa E1, pentru ca apelul la LLM e partea lenta.
- [ ] I4. Draft-uri corecte lingvistic in romana - depinde de E4.

### Securitate (8.2)
- [x] Zero request-uri de retea catre domenii raportate (mock care pica testul)
- [x] Dashboard-ul nu randeaza HTML din mail
- [x] Serviciul asculta doar pe 127.0.0.1
- [x] Sistemul nu trimite mail
- [ ] I5. Testul de prompt injection - vezi G1
- [ ] I6. "Niciun URL nedefanged in DB sau output" - jumatatea cu DB nu se poate
      verifica pana nu exista DB-ul (A1)

### Robustete (8.3)
- [x] Mail malformat nu opreste pipeline-ul (cazul 09 e acoperit)
- [ ] I7. Ollama indisponibil duce la fallback - vezi E5
- [ ] I8. Mailbox indisponibil duce la retry - vezi B1
- [ ] I9. Repornirea nu dublica si nu reproceseaza - vezi B1, depinde de A1

### Calitate (8.4)
- [ ] **I10. Coverage pe parser e sub prag.** Masurat acum, fara corpus:

  | modul | coverage | cerut |
  |---|---|---|
  | `analyzer/__init__.py` | 82% | >70% ✔ |
  | `parser/__init__.py` | **62%** | >70% ✘ |

  Analizorul e peste prag, parser-ul nu. Partea neacoperita e chiar cea scrisa
  recent: `decode_mime_header`, `_clean_body_text`, `_decode_part_payload`,
  ramura de atasamente. Coincide cu zona unde sunt marcate bug-urile - nu e o
  coincidenta.
- [ ] I11. Ridica `COV_MIN` in CI dupa ce I10 e rezolvat (vezi TODO din `ci.yml`).
- [ ] I12. README pe care un coleg il urmeaza pana la un sistem functional in 10
      minute. Acum README-ul are un rand. Vezi TODO-ul din `README.md`.
- [x] CI verde: pytest, ruff, mypy (cu observatia ca pragul de coverage e 0)

---

## J. Reguli de lucru (sectiunea 10)

- [ ] **J1. `docs/decisions/` nu exista.** Foaia cere fiecare decizie de
      arhitectura documentata acolo. Ai deja cel putin patru de scris, si toate
      sunt decizii reale pe care le-ai luat deja:
  - de ce `trusted_partners` slabeste deliberat regula de autentificare (cerut si
    de nota din cazul 06)
  - de ce `domains.py` forteaza snapshot-ul offline in loc sa cheme tldextract
    direct (motivul e deja scris frumos in docstring, doar muta-l)
  - de ce verdictul e determinist si LLM-ul doar scrie text
  - ce model ai ales pentru drafter si pe ce baza (dupa E4)
- [ ] J2. Mesaje de commit descriptive. "updates v2", "updates v3", "ruff checks
      update" nu spun ce s-a schimbat. Peste o luna, cand cauti cand s-a stricat
      ceva, `git log` e primul loc unde te uiti si singurul care nu te ajuta acum.
- [ ] J3. Branch per feature si PR catre main. Momentan totul intra direct pe
      `main`.

---

## Ordinea in care le-as face

1. **Bug-urile marcate `prioritate maxima` in cod** - `grep -rn "TODO(" src/`.
   Nu construi peste ceva ce da verdict gresit.
2. **H1** (adu corpusul) plus testul de verdict din `tests/test_corpus.py`. Fara
   ele lucrezi pe intuitie: nu ai cum sa stii daca o schimbare a stricat ceva.
3. **A1** (baza de date). Deblocheaza F1, F2, B1, I6, I9 dintr-un foc.
4. **E1** (conecteaza Ollama). Pana atunci jumatate din foaie - tot ce tine de
   LLM - e netestata in realitate.
5. **D1 si D2** (Reply-To, Return-Path). Campurile sunt deja parsate, sunt cateva
   randuri fiecare si aduc semnale reale - cel mai bun raport efort/castig din tot
   ce a ramas.
6. Restul, in ordinea din lista.
