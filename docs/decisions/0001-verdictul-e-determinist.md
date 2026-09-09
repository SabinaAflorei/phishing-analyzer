# 0001. Verdictul e determinist, modelul doar scrie text

Data: 2026-09-03
Stare: acceptata

## Context

Sistemul trebuie sa clasifice mail-uri raportate si sa scrie un raspuns catre
colegul care a raportat. Un model de limbaj local (Ollama) e disponibil si ar
putea, in principiu, sa faca ambele.

## Decizie

Verdictul il produce exclusiv analizorul determinist din `triage/analyzer`.
Modelul nu vede niciodata intrebarea "ce este mailul asta" si nu are nicio cale
prin care sa influenteze raspunsul. Primeste doar verdictul deja stabilit si
lista de dovezi, si scrie textul.

## De ce

Un verdict de la un model nu e reproductibil, nu e explicabil si nu e auditabil.
Cand un analist intreaba "de ce a iesit MALICIOUS", raspunsul trebuie sa fie o
lista de semnale cu coduri stabile, nu "asa a zis modelul".

Al doilea motiv e mai important: continutul mailului e text scris de un
atacator. Daca modelul ar decide verdictul, atacatorul ar avea o cale directa
sa scrie in mail instructiuni care schimba verdictul. Cazul 08 din corpus e
exact asta. Cu verdictul determinist, tot ce poate atacatorul sa faca prin
prompt injection e sa strice formularea unui email de raspuns - neplacut, nu
periculos.

## Ce am dat la schimb

Analizorul nu prinde ce nu i-am scris. Un tipar nou de phishing trece pe langa
el pana cand cineva adauga regula. Acceptam: un fals negativ inseamna ca mailul
ajunge la analist, ceea ce e exact ce vrem oricum de la un sistem de triaj.

## Legaturi

- `triage/analyzer/__init__.py` - `SIGNAL_WEIGHT` si `_decide`
- `tests/test_prompt_injection.py`
- [0003](0003-dovezile-se-coroboreaza.md)
