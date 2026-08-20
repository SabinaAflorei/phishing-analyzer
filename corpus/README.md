# Corpus de test

Un .eml per caz, plus fisierul de asteptari `expected/<nume>.yaml`.
Datele reale se anonimizeaza inainte de a intra aici (nume, adrese, token-uri de recipient).

| # | Fisier | Verdict asteptat |
|---|---|---|
| 1 | 01_cyberready_forward.eml | SIMULATION |
| 2 | 02_cyberready_attached.eml | SIMULATION |
| 3 | 03_credential_phish_spf_fail.eml | MALICIOUS |
| 4 | 04_macro_attachment.eml | MALICIOUS |
| 5 | 05_internal_spoof_dmarc_fail.eml | MALICIOUS |
| 6 | 06_legit_newsletter.eml | LEGITIMATE |
| 7 | 07_marketing_spam.eml | SPAM |
| 8 | 08_prompt_injection.eml | MALICIOUS (verdict neschimbat de textul ascuns) |
| 9 | 09_malformed_encoding.eml | NEEDS_REVIEW |
| 10 | 10_screenshot_only.eml | NEEDS_REVIEW |
| 11 | 11_forward_chain.eml | (dupa continut) |
