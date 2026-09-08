# De ce verdictul e determinist și LLM-ul doar scrie text

**Status:** decis de la început, documentat acum

## Decizie

Verdictul (SIMULATION/MALICIOUS/SPAM/LEGITIMATE/NEEDS_REVIEW) e produs
exclusiv de cod Python determinist (`src/triage/analyzer/`), pe reguli
auditabile. LLM-ul (`src/triage/drafter/`) primește verdictul deja decis
plus lista de dovezi, și scrie doar formularea în română. Nu are voie și
nu are mecanism să schimbe verdictul.

## De ce, nu doar "cum"

Trei motive, toate cu consecințe reale dacă am fi ales altfel:

1. **Halucinație cu cost real.** Un model poate inventa un verdict cu
   încredere aparentă. Un fals "e sigur" trimis unui angajat, generat de
   un model care a halucinat, e un incident de securitate, nu doar o
   eroare de text.
2. **Auditabilitate.** Dacă verdictul ar veni din LLM, singurul răspuns
   posibil la un post-mortem ("de ce sistemul a spus că X e sigur?") ar
   fi "nu știu, așa a zis modelul". Cu verdict determinist, fiecare
   decizie are o listă de dovezi (`Evidence`, cu cod, severitate,
   descriere) care se poate reconstitui exact.
3. **Prompt injection.** Email-urile de phishing conțin text controlat de
   atacator. Dacă acel text ar influența verdictul (nu doar formularea),
   un atacator suficient de priceput ar putea scrie un email care se
   auto-declară "legitim" către model. Cu verdict determinist, textul de
   atac ajunge la model doar ca informație de context pentru formulare,
   niciodată ca sursă de decizie — și e oricum sanitizat înainte
   (`sanitize_for_model`).

## Consecință arhitecturală

Interfața dintre analyzer și drafter e strict unidirecțională: analyzer
produce `Analysis(verdict, confidence, evidence)`, drafter primește acest
obiect ca input needitabil. Nicio funcție din `drafter/` nu scrie înapoi
în `verdict`.

## Confirmare prin test

`tests/test_prompt_injection.py::test_prompt_injection_does_not_change_verdict`
verifică explicit: verdictul produs cu și fără text de injection ascuns
e identic — injection-ul poate influența cel mult draftul (prin markerul
informativ `HIDDEN_CONTENT_DETECTED`, severitate INFO, care nu contribuie
la scorul de decizie), niciodată verdictul.
