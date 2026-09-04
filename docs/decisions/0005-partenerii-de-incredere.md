# 0005. `trusted_partners` slabeste deliberat regula de autentificare

Data: 2026-09-03
Stare: acceptata

## Context

Regula generala: `LEGITIMATE` se emite doar cu incredere mare, adica SPF, DKIM
si DMARC toate `pass`. Altfel `NEEDS_REVIEW`.

Problema apare la cazul 06 din corpus, un newsletter comercial real de la un
furnizor la care compania e abonata. Foaia de task spune "toate autentificarile
pass", dar mesajul a fost raportat prin forward inline, iar forward-ul nu
pastreaza `Authentication-Results`. Nu ai pe ce citi un pass.

Aplicata litera cu litera, regula lasa corpusul fara niciun caz `LEGITIMATE`,
iar categoria cea mai delicata - cea in care nu ai voie sa il faci pe coleg sa
se simta prost ca a raportat - nu se mai testeaza niciodata.

## Decizie

`trusted_partners` din `config/company_domains.yaml` deschide o a doua cale
catre `LEGITIMATE`, cu trei conditii simultane:

1. domeniul expeditorului e un partener cunoscut, verificat manual;
2. nu exista niciun semnal explicit de esec de autentificare;
3. exista markeri de newsletter - `List-Unsubscribe`, sau un link ori un text
   de dezabonare in corp.

Scorul cumulat al celorlalte semnale trebuie sa fie tot sub prag. Un partener de
incredere care trimite un atasament `.exe` iese `MALICIOUS`, ca oricine altcineva.

## De ce

E o cale deterministica, nu o euristica: lista e scrisa de om, fisier per
fisier, si fiecare intrare a fost verificata manual. E preferabila alternativei,
care ar fi fost sa slabesc pragul de autentificare pentru toata lumea.

## Ce am dat la schimb

Lista asta slabeste o regula de siguranta. Cine adauga un domeniu aici trebuie
sa stie ca a facut-o: un atacator care reuseste sa trimita din numele unui
partener de incredere, cu un `List-Unsubscribe` in headere, primeste
`LEGITIMATE`. De asta lista e scurta, e in fisierul care nu intra in git, si are
comentariul de avertizare la ea.

## Legaturi

- `config/company_domains.example.yaml`
- `corpus/expected/06_legit_newsletter.yaml`
- `triage/analyzer/__init__.py` - `_classification_evidence`
