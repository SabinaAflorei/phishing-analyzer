# 0007. Nu analizam invelisul raportarii ca si cum ar fi mailul suspect

Data: 2026-09-03
Stare: acceptata

## Context

Cand un coleg trimite o captura de ecran, sau descrie in cuvinte ce a primit,
singurele headere din mesaj sunt ALE LUI. Regulile de autenticitate a
expeditorului rulau pe ele si scoteau, verificat pe cazurile 10 si 11 din
corpus, `INTERNAL_DOMAIN_SPOOF` pe cel mai cuminte om din companie: From-ul lui
e pe un domeniu propriu, iar `Received` nu trece prin infrastructura interna,
pentru ca mesajul a plecat din clientul lui de mail.

Ambele cazuri asteptau `NEEDS_REVIEW` si ieseau `MALICIOUS`.

## Decizie

`is_report_wrapper` decide daca mesajul e un invelis de raportare din care
mesajul original NU s-a putut extrage. Cand e:

- regulile care judeca expeditorul nu ruleaza;
- regulile care judeca continutul nu ruleaza - continutul e textul scris de
  coleg, iar nota cazului 11 spune explicit ca "descrierea NU e o sursa de
  verdict";
- regulile de atasament raman, pentru ca un coleg poate redirectiona chiar
  fisierul periculos;
- se adauga dovada `REPORT_WITHOUT_ORIGINAL`, si verdictul e `NEEDS_REVIEW`.

Criteriul e `report_mailbox` din `config/company_domains.yaml`, plus forma de
raportare. Cheia aia exista de la inceput in config, cu comentariul "Mesajele
CATRE ea sunt raportari; nu se analizeaza wrapper-ul, ci mesajul original din
interior", si nu o citea niciun modul.

## Nota inrudita

Aceeasi problema, alta fateta: la un forward inline, `from_address` vine din
corpul mailului iar `received_chain` din headerele wrapper-ului. A le compara
inseamna a pune intrebarea "a trecut prin infra noastra?" pe lantul gresit.
`ParsedEmail.headers_from_body` marcheaza asta, si `INTERNAL_DOMAIN_SPOOF` nu se
evalueaza cand e adevarat.

## Ce am dat la schimb

O raportare din care nu putem extrage originalul nu primeste niciodata un
verdict automat. Corect: nu avem dovezi tehnice, deci nu avem ce sa afirmam.

## Legaturi

- `triage/analyzer/__init__.py` - `is_report_wrapper`
- `corpus/expected/10_screenshot_inline.yaml`, `11_screenshot_attached.yaml`
