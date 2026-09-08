# De ce `trusted_partners` slăbește deliberat regula de autentificare

**Status:** decis, confirmat prin corpus/expected/06_legit_newsletter.yaml

## Context

Regula strictă de referință: LEGITIMATE se emite doar cu SPF + DKIM +
DMARC pass. Dar un forward inline (cea mai comună formă de raportare) nu
păstrează `Authentication-Results` — headerele originale se pierd la
forward. Aplicată literă cu literă, regula strictă ar face ca niciun
forward să nu poată deveni vreodată LEGITIMATE, chiar și un newsletter
comercial complet inofensiv de la un furnizor cunoscut cu abonament
activ (cazul 06 din corpus).

## Decizie

Un mesaj poate deveni LEGITIMATE și fără autentificare verificabilă,
dacă toate trei sunt adevărate simultan:
1. Domeniul expeditorului e într-o listă `trusted_partners` din
   `company_domains.yaml`, verificată manual de om, nu descoperită
   automat.
2. Nu există niciun semnal explicit de eșec de autentificare (dacă
   `Authentication-Results` există și arată fail, regula nu se aplică).
3. Există un marker de newsletter comercial (subiect cu "newsletter"
   sau "informare", sau un link de dezabonare în corp).

## Notă din depanare reală

Prima variantă a acestei reguli verifica markerul de newsletter *doar*
în subiect. Cazul 06 din corpus are subiectul "Nu mai omite niciun
termen. Descoperă Calendarul JuristPro NEXT!" — fără niciun cuvânt
cheie — și ieșea SPAM în loc de LEGITIMATE, descoperit abia când testele
de comparare cu `expected_verdict` au fost scrise. Fix: markerul
verifică acum și prezența unui link de dezabonare în corp, nu doar
cuvinte cheie în subiect.

## De ce e o slăbire acceptabilă, nu o gaură

`trusted_partners` nu e populat automat — fiecare domeniu adăugat acolo
e o decizie manuală a echipei de securitate. E același nivel de
încredere ca o listă albă administrată manual — nu se poate exploata
prin phishing, pentru că atacatorul nu poate adăuga domenii în acea
listă.

## Trade-off asumat

Dacă un partener din `trusted_partners` e vreodată compromis, acest
mesaj ar putea trece ca LEGITIMATE fără autentificare. Riscul e acceptat
pentru că lista e mică, curatoriată manual, și revizuită — nu pentru
orice domeniu extern.
