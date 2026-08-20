# Phishing report triage assistant

Sistem local care ingereaza raportarile de phishing, le analizeaza determinist,
pregateste un draft de raspuns si le prezinta intr-un dashboard pe localhost.

## Limite (nenegociabile)
- Nu trimite niciun mail. Analistul copiaza si trimite manual.
- Nu acceseaza URL-urile raportate. Fara DNS, fara HTTP, fara imagini remote.
- Nu deschide si nu executa atasamente.
- Nu blocheaza nimic. Nu inlocuieste analistul.

## Pornire in 10 minute
```bash
cp .env.example .env
cp config/settings.example.yaml config/settings.yaml
source .venv/bin/activate
make test          # reteaua e blocata in teste, asa trebuie sa fie
make run           # http://127.0.0.1:8000
```

## Comenzi
| Comanda | Ce face |
|---|---|
| `make ci` | ruff + mypy + pytest, tot ce trebuie verde inainte de PR |
| `make test` | teste, cu socket-urile blocate |
| `make run` | dashboard pe 127.0.0.1:8000 |
| `scripts/check_bind_localhost.sh` | verifica ca nimic nu e expus in afara loopback |
| `scripts/fix_perms.sh` | 700/600 pe data/ |

## Structura
```
src/triage/{fetcher,parser,analyzer,drafter,dashboard}   componente independente
config/                 cyberready.yaml, company_domains.yaml, settings.yaml
corpus/                 cele 11 cazuri de test + verdictele asteptate
docs/decisions/         cate un ADR per decizie de arhitectura
data/                   .eml brute (700/600, exclus din git si backup)
```

## Ordinea recomandata de lucru
1. Parser + corpus (cazurile 1, 2, 10, 11) — extragerea mesajului original.
2. Analizor: fingerprint CyberReady (cel mai mare castig imediat), apoi autentificare.
3. Dashboard read-only pe verdicte.
4. Drafter cu template static, apoi Ollama peste el.
5. Feedback capture (versiune originala vs finala a draft-ului).
