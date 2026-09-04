# 0004. Modelul pentru drafter

Data: 2026-09-03
Stare: PROPUSA - masuratoarea lipseste

## Context

Drafter-ul scrie in romana literara, cu diacritice, adresare formala, si
constrangeri diferite pe fiecare categorie de verdict. `llama3.1:8b` apare in
`settings.example.yaml` si in `.env.example` ca valoare initiala, cu mentiunea
explicita ca e "punct de pornire, NU o decizie".

## Stare

**Nemasurat.** Ollama nu e instalat pe masina pe care s-a facut lucrarea asta,
deci `scripts/eval_model.py` nu a rulat pe niciun model. Decizia ramane
deschisa; nu inchide fisierul asta pana nu ai numere.

## Ce trebuie facut

```bash
python3 scripts/eval_model.py --baseline
python3 scripts/eval_model.py \
    --models qwen2.5:7b-instruct,llama3.1:8b,mistral-nemo:12b \
    --runs 5 --out build/eval.md
```

Scriptul verifica automat structura de email, diacriticele corecte (virgula, nu
cedila), lungimea, si constrangerile per categorie - de exemplu ca raspunsul
pentru `SIMULATION` nu scapa cuvantul "simulare", sau ca cel pentru `LEGITIMATE`
nu il face pe coleg sa se simta prost ca a raportat.

Reperul e `--baseline`: sabloanele statice, scrise de om, care trec 100%. Un
model care nu se apropie de reper pe o categorie inseamna ca sablonul static e
raspunsul corect pentru categoria aia - lucru pe care arhitectura il permite
explicit.

## Criteriu de oprire

Peste 30s la cald inseamna ca modelul nu incape in bugetul din 8.1. Calea
deterministica dureaza ~3ms per mail, deci practic tot bugetul e al modelului.

## Cand ai numerele

Completeaza tabelul aici, pune modelul in `config/settings.yaml` la `llm.model`,
si actualizeaza sectiunea "Modelul ales" din README.

| Model | Rulari corecte | Timp mediu (cald) | Timp maxim | Esecuri frecvente |
|---|---|---|---|---|
| _de completat_ | | | | |
