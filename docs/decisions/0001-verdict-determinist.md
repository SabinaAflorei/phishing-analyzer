# 0001 - Verdictul e determinist, LLM-ul doar scrie textul

Data: (completeaza)
Status: acceptat

## Context
Textul unui mail de phishing e controlat de atacator.

## Decizie
Verdictul se produce din reguli auditabile in Python. LLM-ul primeste doar
verdictul + dovezile si redacteaza raspunsul. Nu poate schimba verdictul.

## Consecinte
- Orice verdict se poate explica intr-un post-mortem, semnal cu semnal.
- Prompt injection nu poate muta verdictul, pentru ca modelul nu il produce.
- Costul: regulile trebuie intretinute manual.
