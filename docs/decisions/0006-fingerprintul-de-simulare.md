# 0006. Domeniul singur nu e niciodata suficient pentru SIMULATION

Data: 2026-09-03
Stare: acceptata
Inlocuieste: comportamentul de dinainte, in care domeniul decidea singur

## Context

Platforma de simulare (CyberReady) trimite din domenii cunoscute. Prima versiune
trata potrivirea de domeniu ca dovada suficienta, iar semnalele de confirmare
(Message-ID, IP de expeditie, hostname de tracking) intrau toate in acelasi SAU.

Doua gauri, amandoua verificate:

- `attacker@totally-evil.tld` cu un link catre `https://inner.website/...` iesea
  `SIMULATION 1.0`. `inner.website` e scris in `config/cyberready.yaml`, care e
  public in repo.
- `From: hp@notificaton.online`, fara niciun alt semnal, iesea la fel. Iar
  forward-urile inline, formatul principal de raportare, nu au
  `Authentication-Results`, deci nici garda de `spf=fail` nu ajuta acolo.

Un fals pozitiv aici inseamna ca un phishing real primeste raspunsul bland de
"a fost doar o simulare". Comentariul din capul lui `cyberready.yaml` spune
explicit ca asta e inacceptabil.

## Decizie

Semnalele sunt impartite in doua clase:

- **Tari**: sufixul de Message-ID in `Message-ID` / `In-Reply-To` /
  `References`, identitatea DKIM din `Authentication-Results`, IP-ul de
  expeditie din lantul `Received`, headerele proprietare `X-CRPS` si
  `X-Virtual-MTA`. Toate sunt greu de falsificat sau nu supravietuiesc unui
  forward, deci nu le poate pune atacatorul.
- **Slabe**: hostname de tracking in URL-uri. Un link il pune oricine in corpul
  mailului.

Regula: **domeniu cunoscut plus orice semnal**, sau **fara domeniu, un semnal
tare**. Domeniul singur nu ajunge niciodata, semnalul slab nu decide niciodata
singur.

In acelasi timp, lista hardcodata `CYBEREADY_LEGACY_DOMAINS` din analizor s-a
mutat in `config/cyberready.yaml`. Erau doua surse de adevar care se
contraziceau, si cea din cod castiga in tacere.

## Ce am dat la schimb

O simulare fara niciun semnal de confirmare iese `NEEDS_REVIEW` in loc de
`SIMULATION`, deci ajunge la analist. Asta e schimbul corect: un fals negativ
costa cateva minute de om, un fals pozitiv costa un incident.

## Legaturi

- `triage/analyzer/__init__.py` - `is_cybeready_simulation`
- `tests/test_analyzer.py` - `test_link_de_tracking_singur_nu_da_simulation_unui_strain`
