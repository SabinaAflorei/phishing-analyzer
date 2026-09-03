# TODO - ce a mai ramas din foaia de task

Legenda: `[x]` gata &nbsp; `[~]` partial &nbsp; `[ ]` nefacut

Bug-urile marcate in cod cu `TODO(` sunt toate rezolvate. Verifica:

```
grep -rn "TODO(" src/ config/ tests/ .github/     # nu mai returneaza nimic
```

---

## Unde esti acum

Cele sase componente exista si comunica printr-o baza de date SQLite. Pipeline-ul
merge cap-coada: `triage ingest` umple coada, dashboard-ul o arata, butoanele
salveaza, iar ce apesi in browser se vede din CLI - adica baza de date chiar
decupleaza componentele, nu doar pe hartie.

357 de teste trec, zero sarite, 94% acoperire. Ruff si mypy strict sunt verzi.

**Ce a mai ramas depinde aproape tot de lucruri din afara codului**: corpusul
real, o masina cu Ollama, si discutia cu mentorul despre mailbox.

---

## A. Arhitectura (sectiunea 3)

- [x] **A1. Baza de date.** `triage/db.py`, tabel `reports`, idempotenta pe
      `eml_sha256` cu Message-ID ca a doua cheie. `triage/pipeline.py` e drumul
      complet, folosit de CLI, dashboard si poll.
- [x] **A2. `config/settings.yaml` se citeste.** `triage/settings.py`, pe
      pydantic-settings. YAML pentru tot ce nu e secret, `.env` doar pentru
      credentialele IMAP - ca sa nu existe doua adevaruri pentru aceeasi valoare.
      `llm.base_url` si `dashboard.host` sunt validate ca loopback la pornire.
      Fisierele lipsa cad pe varianta `.example`, cu avertisment in log.

## B. Fetcher (sectiunea 6.1)

- [x] Conectare IMAP read-only cu app password din `.env`
- [x] Poll la interval configurabil (`triage poll`, implicit 300s din settings)
- [x] Evidenta procesatelor in baza de date, fara sa se atinga mesajele
- [x] Repornirea nu reproceseaza si nu dublica
- [x] Retry cu asteptare crescatoare la mailbox indisponibil
- [ ] **B1. Discutia cu mentorul inainte de mailbox-ul real** (sectiunea 10).
      Codul e gata si testat pe un server fals; `.env` e gol, deci nu se conecteaza
      nicaieri. Nu completa `TRIAGE_IMAP_HOST` inainte de discutie.

## C. Parser (sectiunea 6.2)

- [x] Display-name separat de adresa (`from_display_name`)
- [x] Corp HTML pastrat separat (`body_html`), folosit doar pentru semnale
- [x] Perechi text-ancora + href (`links`)
- [x] Arhive protejate cu parola, din flagul de criptare al headerului ZIP
- [x] In plus: `reporter_address` (colegul care a raportat, separat de expeditor),
      `to_addresses`, `header_names`, `sent_at`, `headers_from_body`

## D. Analizor determinist (sectiunea 6.3)

- [x] **D1.** Reply-To diferit de From
- [x] **D2.** Return-Path nepotrivit (sarit pe listele de mail, unde e normal)
- [x] **D3.** Homoglife si punycode / IDN, prin `confusable-homoglyphs`
- [x] **D4.** Nepotrivire display-name / domeniu real
- [x] **D5.** Urgenta artificiala, cereri de credentiale, discrepanta text-link
- [x] **D6.** Coroborare: toate regulile ruleaza, ponderile stau intr-un tabel,
      doua praguri decid. Vezi `docs/decisions/0003-dovezile-se-coroboreaza.md`.

## E. Drafter (sectiunea 6.4)

- [x] **E1.** Ollama conectat (`triage/llm.py`). Clientul se paseaza din pipeline.
- [x] **E2.** Timeout pe apel, din `llm.timeout_seconds`
- [x] **E3.** Trunchiere la `llm.max_input_chars`, valoarea din config
- [ ] **E4. Ruleaza `scripts/eval_model.py` si alege modelul.** Nefacut: Ollama
      nu e instalat pe masina pe care s-a lucrat. `llama3.1:8b` ramane o valoare
      mostenita, nu o decizie. Vezi `docs/decisions/0004-modelul-pentru-drafter.md`
      pentru comanda exacta si criteriul de oprire.
- [x] **E5.** Test de fallback cu Ollama picat

## F. Dashboard (sectiunea 6.5)

- [x] **F1.** "Marcheaza trimis" si "Escaleaza" salveaza. O actiune necunoscuta
      spune ca nu s-a schimbat nimic, in loc sa minta cu "succes".
- [x] **F2.** Statusul si corectiile persista; filtrele pe status si verdict merg
- [x] **F3.** Distributia de verdicte si matricea de corectii

## G. Securitate (sectiunea 4)

- [x] **G1.** Testul de prompt injection - nu mai e `xfail`
- [x] **G2.** Curatarea textului ascuns inainte de model (display:none, 1px,
      alb pe alb, opacity 0, visibility hidden)
- [x] **G3.** Validarea output-ului modelului, testata pe ambele ramuri
- [ ] **G4. Snapshot al VM-ului inainte de prima ingestie reala.** Nu e cod.
      E pe lista de verificare din README.
- [x] **G5.** `data/` are `CACHEDIR.TAG`, respectat de borg, restic si
      `tar --exclude-caches`
- [ ] **G6. Modulul de imbogatire externa** - optional prin foaie, nefacut.
      Comutatorul exista in settings si e implicit oprit. Daca il faci: submisie
      privata implicit si curatarea tokenului per-destinatar din URL inainte de
      trimitere (4.6). `strip_url_tokens` din `triage/defang.py` face deja a doua
      jumatate.

## H. Corpus de test (sectiunea 7)

- [~] **H1. Corpusul real lipseste de pe masina asta.**
      `scripts/make_synthetic_corpus.py` genereaza 12 inlocuitori cu aceeasi
      structura si aceleasi semnale, deci testele ruleaza si in CI. **Nu e acelasi
      lucru** - vezi `docs/decisions/0008-corpus-sintetic.md`. Cand aduci corpusul
      real, il copiezi peste (aceleasi nume) si rulezi din nou testele.
- [x] **H2.** Cazul 12 e documentat in `corpus/README.md` si in `notes:` din yaml
- [x] **H3.** `must_contain_evidence` completat pe toate cele 12 cazuri

## I. Criterii de acceptanta (sectiunea 8)

### Functionale (8.1)
- [~] **I1.** Toate cazurile primesc verdict corect - **pe corpusul sintetic**.
      Testul exista (`test_verdictul_e_cel_asteptat`) si trece 12/12. Se
      reconfirma pe corpusul real cand ajunge.
- [x] **I2.** Precizie pe detectia CyberReady: domeniul singur nu mai da
      niciodata SIMULATION. Vezi `docs/decisions/0006-fingerprintul-de-simulare.md`.
- [~] **I3.** Sub 30s de la ingestie la draft. Calea deterministica: ~3ms per
      mail, testata. Partea cu modelul se masoara la E4.
- [ ] **I4.** Draft-uri corecte lingvistic in romana - depinde de E4.

### Securitate (8.2)
- [x] Zero request-uri de retea catre domenii raportate
- [x] Dashboard-ul nu randeaza HTML din mail
- [x] Serviciul asculta doar pe 127.0.0.1
- [x] Sistemul nu trimite mail
- [x] **I5.** Testul de prompt injection
- [x] **I6.** Niciun URL nedefanged in baza de date sau in output

### Robustete (8.3)
- [x] Mail malformat nu opreste pipeline-ul
- [x] **I7.** Ollama indisponibil duce la fallback
- [x] **I8.** Mailbox indisponibil duce la retry
- [x] **I9.** Repornirea nu dublica si nu reproceseaza

### Calitate (8.4)
- [x] **I10.** Coverage: parser 91%, analizor 99%, total 94% (prag cerut: 70%)
- [x] **I11.** `COV_MIN` ridicat la 85 in CI
- [x] **I12.** README cu drum complet in 10 minute
- [x] CI verde: pytest, ruff, mypy

## J. Reguli de lucru (sectiunea 10)

- [x] **J1.** `docs/decisions/` - opt decizii scrise
- [x] **J2.** Mesaje de commit descriptive
- [ ] **J3. PR catre main.** Lucrarea e pe `feat/todo-completion`. Deschide PR-ul
      cand esti gata.

---

## Ce as face in continuare

1. **E4** - cea mai mare bucata ramasa, si singura care blocheaza doua criterii
   (I3 si I4). Are nevoie de o masina cu Ollama, nimic altceva.
2. **H1** - adu corpusul real si rerulează. Aici se afla daca parserul chiar
   descurca ce ies clientii de mail din realitate.
3. **B1** - discutia cu mentorul, apoi completeaza `.env`.
4. **G4** - snapshot inainte de prima ingestie reala. Se uita usor.
5. **G6** - imbogatirea externa, daca o vrei. E optionala prin foaie.
