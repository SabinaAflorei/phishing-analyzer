# 0003. Verdictul e o suma de dovezi, nu prima regula care se potriveste

Data: 2026-09-03
Stare: acceptata
Inlocuieste: comportamentul de dinainte, in care fiecare regula facea `return`

## Context

Prima versiune a analizorului avea regulile una sub alta, si fiecare intorcea
un verdict imediat ce se potrivea. Consecinte masurate:

- Regula de TLD cu risc ridicat rula inaintea celei de partener de incredere,
  deci un newsletter legitim pe `.online` iesea `MALICIOUS`.
- O evidenta cu `Severity.MEDIUM` producea `MALICIOUS 0.9`, pentru ca apelantul
  nu se uita la severitate.
- Semnalele slabe nu se puteau aduna: Reply-To nepotrivit, urgenta artificiala
  si cerere de credentiale nu insemnau nimic separat, si nu aveau cum sa
  insemne ceva impreuna.

## Decizie

`_collect_evidence` ruleaza TOATE regulile si aduna dovezile. `_decide`
transforma lista in verdict, dupa un tabel de ponderi (`SIGNAL_WEIGHT`) si doua
praguri.

- **1.0** = suficient singur pentru `MALICIOUS`. Doar trei semnale au voie:
  esec de autentificare, atasament periculos, spoofing de domeniu propriu.
- Sub 1.0 = are nevoie de coroborare.
- Peste **0.4** dar sub 1.0 = `NEEDS_REVIEW`, cu o dovada care spune ca
  semnalele s-au coroborat fara sa atinga pragul automat.

Regula pe care o respecta tot fisierul: severitatea unei dovezi si greutatea ei
in scor merg impreuna.

## De ce

Foaia cere ca semnalele de continut sa aiba "pondere mica, dar coroboranta".
Asta presupune sa le aduni, nu sa iesi la prima.

Un tabel unic de ponderi face politica de decizie citibila dintr-o privire si
calibrabila fara sa umbli prin reguli. Un test verifica automat ca fiecare cod
de dovada produs de analizor are o pondere - altfel ar conta zero in tacere.

## Ce am dat la schimb

Pragurile sunt numere alese de om, nu invatate din date. Se vor regla dupa
prima luna de folosire reala; pagina de statistici arata exact ce se corecteaza
si in ce, adica de unde sa incepi.

## Legaturi

- `triage/analyzer/__init__.py`
- `tests/test_analyzer.py` - `test_semnalele_slabe_se_aduna_pana_la_prag`
