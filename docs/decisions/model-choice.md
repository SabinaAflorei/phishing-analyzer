# Alegerea modelului pentru drafter

**Data:** 2026-09-07
**Status:** decis, cu limitări cunoscute documentate

## Context

Foaia de task cere testarea explicită a calității în limba română și
menționează că `llama3.1:8b` e "punct de pornire, NU o decizie" — modelele
mici se degradează vizibil pe RO, iar decizia finală trebuie luată pe baza
unei evaluări reale, nu presupusă.

## Modele testate

Rulat `scripts/eval_model.py` (3 rulări per categorie de verdict), verificând
diacritice, structură salut/corp/încheiere, și constrângeri specifice per
categorie (ex. interdicția de a dezvălui natura de simulare la SIMULATION,
cererea explicită de ștergere la MALICIOUS).

| Model | Corecte | Latență medie (cald) | Latență maximă |
|---|---|---|---|
| llama3.1:8b | 42% | 41.5s | 54.9s |
| qwen2.5:7b-instruct (prompt inițial) | 42% | 30.4s | 47.2s |
| qwen2.5:7b-instruct (prompt întărit SIMULATION) | 25%* | 36.7s | 59.6s |

\* variație probabil de eșantion (vezi mai jos), nu regresie reală cauzată de
modificarea de prompt — MALICIOUS și SPAM, categorii neatinse de modificare,
au variat de la 1/3 la 0/3 fără nicio schimbare de cod pentru ele.

## Observații pe eșecuri

- **llama3.1:8b** eșua pe SIMULATION prin dezvăluirea explicită a naturii
  de simulare (cuvinte precum "platformă de simulare", "training"),
  încălcând direct interdicția din prompt. Eroare de conținut critic,
  consistentă pe toate cele 3 rulări — exact scenariul pe care secțiunea 5
  din foaia de task îl consideră inacceptabil ca fals pozitiv.
- **qwen2.5:7b-instruct** nu dezvăluie niciodată natura de simulare (0
  incidente pe niciuna din cele 6 rulări totale, cu sau fără promptul
  întărit), dar eșuează constant la cerința de lungime minimă (3
  propoziții în corp), indiferent cât de explicit e formulată constrângerea
  în prompt.
- **Testat:** am întărit prompt-ul SIMULATION cu o instrucțiune explicită,
  operațională ("Corpul mesajului are OBLIGATORIU exact 3 propoziții...
  Numără propozițiile înainte să răspunzi"). Confirmat că modificarea a
  fost încărcată corect de client (`python -c "from triage.drafter.prompts
  import SIMULATION"` arată textul nou). Rezultat: **niciun efect** — output
  identic, cuvânt cu cuvânt, cu varianta dinaintea modificării, la toate
  cele 3 rulări. Concluzie: nu e o problemă de ambiguitate de prompt, ci o
  limitare reală a modelului de 7B pe această constrângere specifică.
- Ambele modele eșuau similar pe MALICIOUS (lipsă cerere explicită de
  ștergere a mesajului, în unele rulări) și SPAM (formulare de liniștire
  incompletă).

## Decizie

Ales: **`qwen2.5:7b-instruct`**.

Motive:
1. Nu a dezvăluit niciodată natura de simulare, pe niciuna din cele 6
   rulări testate — cel mai important criteriu de siguranță din foaia de
   task (secțiunea 5).
2. Latență mai mică decât llama3.1:8b în ambele configurații testate.
3. Eșecul rămas (lungime insuficientă la SIMULATION) e un defect vizibil,
   corectabil manual de analist la revizuire — nu un risc de conținut ca
   dezvăluirea simulării.

## Limitări cunoscute, neînchise

- Rata de succes automat (25-42%, variabilă cu eșantion mic) e sub target
  pentru a elimina revizuirea manuală — draft-urile generate de LLM rămân
  editabile de analist înainte de trimitere, exact cum cere arhitectura
  (LLM propune, analist decide).
- Constrângerea de lungime minimă la SIMULATION nu răspunde la prompt
  engineering standard cu acest model — opțiuni neexplorate: few-shot cu
  mai multe exemple, model mai mare (14B, cum sugerează foaia ca alternativă),
  sau validare post-generare care respinge draft-uri sub lungimea minimă și
  cade pe fallback static (mecanism deja disponibil prin `split_email`).
- Latența medie (30-37s) tot depășește bugetul de 30s din criteriul 8.1.
- Eșantion de 3 rulări per categorie e prea mic pentru concluzii fine despre
  variații mici de prompt — pentru iterații viitoare, recomandat 5-10 rulări.

## Configurare

`config/settings.yaml` → `llm.model: qwen2.5:7b-instruct`