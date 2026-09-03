# 0008. Un corpus sintetic, generat de script, langa cel real

Data: 2026-09-03
Stare: acceptata

## Context

`corpus/eml/` contine raportari reale si e in `.gitignore`. Pe orice masina fara
el - o clona noua, CI, laptopul altui coleg - 37 de teste se sareau si niciun
criteriu functional din 8.1 nu se putea verifica. Adica exact testele care
conteaza nu rulau nicaieri in afara de un singur VM.

## Decizie

`scripts/make_synthetic_corpus.py` genereaza cele 12 cazuri cu date inventate,
pastrand structura MIME si semnalele fiecarui caz: forward inline cu
In-Reply-To, mesaj atasat `message/rfc822` cu headere complete, atasament
`.docm`, captura inline cu Content-ID, mojibake si base64 stricat, si asa mai
departe.

Fisierele generate raman gitignored, ca si cele reale. Scriptul e artefactul
care intra in git.

## Ce NU inseamna asta

Corpusul sintetic nu inlocuieste corpusul real. Un test care trece pe el
demonstreaza ca pipeline-ul functioneaza pe forma pe care o astept EU de la
mailuri - nu ca functioneaza pe mailurile care chiar vin. Diferenta e exact
locul unde traiesc bug-urile interesante: clienti de mail care pliaza headerele
altfel, encoding-uri neasteptate, structuri MIME pe care nu le-am imaginat.

Cand corpusul real ajunge pe VM, se copiaza peste (fisierele au aceleasi nume)
si se ruleaza din nou testele. Abia atunci ai raspunsul adevarat.

## Ce am castigat imediat

Doua bug-uri reale, gasite de corpusul sintetic in prima rulare: cazurile 10 si
11 ieseau `MALICIOUS` in loc de `NEEDS_REVIEW`. Vezi
[0007](0007-invelisul-de-raportare.md).

## Legaturi

- `scripts/make_synthetic_corpus.py`
- `tests/test_corpus.py` - `test_verdictul_e_cel_asteptat`
