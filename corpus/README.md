# Corpusul de test

## Ce e aici, ce nu e

- `expected/*.yaml` — **intra in git**. Verdictul asteptat si codurile de dovezi
  obligatorii pentru fiecare caz. Fara continut sensibil.
- `eml/*.eml` — **NU intra in git**. Raportari reale: nume si adrese de colegi,
  contacte externe, URL-uri de tracking cu token per destinatar (sectiunea 4.6).
- `msg/*.msg` — **NU intra in git**. Sursele Outlook, inainte de conversie.

Fara `eml/`, testele care compara verdictele se sar cu un mesaj clar, in loc sa
pice.

## Cum ajunge corpusul real pe VM

Se copiaza prin canalul discutat cu mentorul, nu prin repo si nu prin mail.
Dupa copiere:

```bash
chmod 700 corpus/eml
chmod 600 corpus/eml/*.eml     # sau: ./scripts/fix_perms.sh
```

Un test verifica permisiunile (`test_eml_e_privat`) si pica daca sunt altele.

## Daca nu ai inca corpusul real

```bash
python3 scripts/make_synthetic_corpus.py
```

Genereaza cele 12 cazuri cu date inventate, cu aceeasi structura MIME si
aceleasi semnale. Fisierele au aceleasi nume ca cele reale, deci cand primesti
corpusul adevarat il copiezi pur si simplu peste.

**Nu e acelasi lucru.** Vezi `docs/decisions/0008-corpus-sintetic.md`.

## Conversia din .msg

```bash
pip install -r requirements-corpus.txt      # unelte folosite O SINGURA DATA
python3 scripts/msg_to_eml.py corpus/msg/1.msg -o corpus/eml/01_cyberready_forward.eml
```

`extract-msg` trage oletools, cryptography si inca vreo zece pachete. Pipeline-ul
nu vede niciodata un `.msg`, deci ele nu se instaleaza pe masina care ruleaza
sistemul.

## Cele 12 cazuri

| Caz | Verdict asteptat | Ce testeaza |
|---|---|---|
| 01 | SIMULATION | forward inline; headerele originale se pierd, In-Reply-To supravietuieste |
| 02 | SIMULATION | acelasi mesaj ca atasament `message/rfc822`, cu headere complete |
| 03 | MALICIOUS | phishing de credentiale: lookalike, SPF/DKIM/DMARC fail, text-link nepotrivit |
| 04 | MALICIOUS | atasament `.docm`; verdict din metadate, fisierul nu se deschide |
| 05 | MALICIOUS | spoofing de domeniu intern; depinde de `company_domains.yaml` |
| 06 | LEGITIMATE | newsletter de partener de incredere, fara Authentication-Results |
| 07 | SPAM | publicitate nesolicitata cu link de dezabonare |
| 08 | MALICIOUS | prompt injection ascunsa in patru feluri; verdictul nu are voie sa se schimbe |
| 09 | NEEDS_REVIEW | mail stricat in cinci feluri; nu are voie sa opreasca pipeline-ul |
| 10 | NEEDS_REVIEW | doar captura de ecran, inline, fara text |
| 11 | NEEDS_REVIEW | captura atasata plus descriere scrisa de om, care nu e dovada |
| 12 | NEEDS_REVIEW | BONUS, in afara celor 11 din foaie; atasament taiat de gateway |

Cazul 12 nu e in foaia de task. Exista ca sa verifice ca analizorul nu forteaza
un verdict cand nu are pe ce sa se sprijine — vezi `notes:` din yaml-ul lui.
