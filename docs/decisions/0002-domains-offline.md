# 0002. Impartirea hostname-urilor se face pe un instantaneu offline

Data: 2026-09-03
Stare: acceptata

## Context

Analizorul compara domenii: lookalike fata de domeniile proprii, potrivire de
subdomeniu pe fingerprintul de simulare, TLD-uri cu risc ridicat. Toate au
nevoie sa stie unde se termina sufixul public si unde incepe domeniul
inregistrabil - `co.uk` nu e acelasi lucru cu `uk`.

`tldextract` face exact asta, dar cu setarile implicite descarca lista de
sufixe de la publicsuffix.org la prima folosire si o tine intr-un cache legat de
calea venv-ului.

## Decizie

`triage/domains.py` construieste un singur extractor, cu
`suffix_list_urls=()` si `fallback_to_snapshot=True`, si toata lumea trece prin
el. Nimeni nu cheama `tldextract` direct.

## De ce

Un sistem descris ca offline-first nu are voie sa iasa in retea ca sa afle ce e
un TLD. Fara instantaneu:

- pe VM merge, pentru ca cineva a incalzit cache-ul o data;
- in CI, pe un venv nou, face un request HTTP la pornire;
- in teste, unde socket-urile sunt blocate, pica cu o eroare care nu seamana
  deloc cu cauza reala.

Cu instantaneul, comportamentul e identic pe orice masina si la orice moment.

## Ce am dat la schimb

Instantaneul e fix. Cand apar TLD-uri noi, se actualizeaza `tldextract` in
`requirements.txt` - deliberat, cu un PR, nu pe tacute la runtime.

## Nota

`is_subdomain_of` compara pe eticheta, nu cu `endswith`. Altfel
`notcybereadysmtp.com` ar trece drept subdomeniu al `cybereadysmtp.com`, iar un
fals pozitiv pe fingerprintul de simulare e exact ce nu avem voie sa producem.

## Legaturi

- `triage/domains.py`, `tests/test_domains.py`
