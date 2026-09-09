#!/usr/bin/env python3
"""Evaluare a unui model local pe sarcina reala a drafter-ului.

Nu "pare bine sau nu": ruleaza aceleasi cazuri de N ori si verifica automat tot
ce se poate verifica (structura de email, diacritice, lungime, constrangeri de
continut per categorie), apoi iti arata textul ca sa il citesti tu.

System prompt-urile si template-urile vin din src/triage/drafter/prompts.py -
acelasi fisier pe care il foloseste drafter-ul in productie. Ce calibrezi aici
ajunge direct in sistem.

NU cere Ollama. Foloseste ACELEASI clientii ca productia (`triage.llm`), deci
merge la fel pe `llama-server` (llama.cpp), vLLM sau LM Studio - orice server cu
API OpenAI. Fara argumente ia runtime-ul, adresa si modelul din
`config/settings.yaml`, adica exact ce va folosi sistemul.

Utilizare:
    python3 scripts/eval_model.py                     # ce scrie in settings.yaml
    python3 scripts/eval_model.py --runs 5
    python3 scripts/eval_model.py --models qwen2.5:7b-instruct,llama3.1:8b
    python3 scripts/eval_model.py --api openai --base-url http://127.0.0.1:8080
    python3 scripts/eval_model.py --out build/eval-llama3.1-8b.md
    python3 scripts/eval_model.py --baseline          # evalueaza template-urile statice
    EVAL_DEBUG=1 python3 scripts/eval_model.py --runs 1

Doar stdlib, si doar loopback: `base_url` trece prin acelasi validator ca in
productie, deci un server extern e respins inainte sa plece vreun octet.
"""

from __future__ import annotations

import argparse
import os
import re
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from triage.drafter.prompts import (
    STATIC_TEMPLATES,
    SYSTEM_PROMPTS,
    split_email,
)
from triage.llm import LLMClient, OllamaUnavailable, build_llm_client
from triage.settings import LLMSettings, get_settings

DEBUG = bool(os.getenv("EVAL_DEBUG"))


# ---------------------------------------------------------------------------
# Cazuri de test
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    category: str
    reporter: str
    evidence: list[str]

    def user_prompt(self) -> str:
        dovezi = "\n".join(f"- {e}" for e in self.evidence)
        return (
            f"Raportor: {self.reporter}\n"
            f"Verdict: {self.category}\n"
            f"Dovezi:\n{dovezi}\n\n"
            f"Scrie emailul de raspuns."
        )


CASES = [
    Case(
        "SIMULATION",
        "Andrei Popa",
        [
            "Expeditorul apartine platformei interne de simulare.",
            "Link-urile duc catre infrastructura de training.",
        ],
    ),
    Case(
        "MALICIOUS",
        "Maria Ionescu",
        [
            "SPF a esuat pentru domeniul expeditorului.",
            "Domeniul imita domeniul companiei printr-un caracter diferit.",
            "Pagina din link cere utilizator si parola.",
        ],
    ),
    Case(
        "SPAM",
        "Vlad Dumitrescu",
        [
            "Newsletter comercial nesolicitat.",
            "Contine buton de dezabonare functional.",
            "Fara atasamente si fara cereri de date.",
        ],
    ),
    Case(
        "LEGITIMATE",
        "Elena Stan",
        [
            "SPF, DKIM si DMARC au trecut toate.",
            "Domeniul expeditorului este un furnizor cunoscut al companiei.",
            "Fara atasamente si fara cereri de credentiale.",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Tipare pentru verificari
# ---------------------------------------------------------------------------

CORRECT_DIACRITICS = set("ăâîșțĂÂÎȘȚ")
WRONG_CEDILLA = set("şţŞŢ")  # cedila in loc de virgula - greseala clasica

# "click" si "email" sunt imprumuturi normale in romana - nu le semnalam.
ENGLISH_LEAK = re.compile(
    r"\b(the|please|thank you|thanks|security|report|kindly|regards|sincerely|however)\b",
    re.I,
)
CALQUES = re.compile(
    r"\b(aplica pentru|adreseaz[ăa] problema|face sens|[îi]n ordine s[ăa])\b", re.I
)

PLACEHOLDER = re.compile(r"\[[^\]]*\]")
LIST_LINE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s", re.M)

THANKS = re.compile(r"\bv[ăa] mul[țt]umim\b", re.I)
GOOD_CALL = re.compile(
    r"(bine c[ăa] a[țt]i raportat|decizia corect[ăa]|a[țt]i procedat corect|"
    r"corect c[ăa] (ni )?l-a[țt]i|v[ăa] [îi]ncuraj[ăa]m s[ăa] (face[țt]i|raporta[țt]i))",
    re.I,
)
BLAME = re.compile(
    r"(nu era cazul|de data aceasta nu|a[țt]i putut observa|[îi]n viitor pute[țt]i verifica|"
    r"din fericire|nu v[ăa] face[țt]i griji degeaba|era evident|se putea observa)",
    re.I,
)
CLICK_Q = re.compile(r"(accesat|dat click|introdus|completat|deschis).{0,60}\?", re.I | re.S)
DELETE_ASK = re.compile(r"(șterge|sterge|elimina|[îi]l [șs]terge[țt]i)", re.I)
DANGER = re.compile(r"(periculos|d[ăa]un[ăa]tor|[îi]ncearc[ăa] s[ăa] ob[țt]in|frauduloas?)", re.I)
UNSUB = re.compile(r"(dezabon)", re.I)
BLOCK = re.compile(r"(blocare|bloca[țt]i|blocarea|blocheaz)", re.I)
CALM = re.compile(r"(nu prezint[ăa] un risc|nepericulos|f[ăa]r[ăa] pericol|nu reprezint[ăa])", re.I)
LEAKS_SIMULATION = re.compile(
    r"(simulare|simulat|exerci[țt]iu|test[a-zăâîșț]*|antrenament|campanie|training|"
    r"instruire|fictiv)",
    re.I,
)
ANALYSIS_PROMISE = re.compile(r"(urmeaz[ăa]|va fi|vor fi|[îi]nregistrat|analiz)", re.I)
VERDICT_LEAK = re.compile(r"(periculos|legitim|sigur|nepericulos|phishing|nu prezint[ăa])", re.I)


def count_sentences(text: str) -> int:
    return len([s for s in re.split(r"[.!?]+", text) if s.strip()])


def first_name(full_name: str) -> str:
    parts = full_name.split()
    return parts[0] if parts else ""


def last_name(full_name: str) -> str:
    parts = full_name.split()
    return parts[-1] if len(parts) > 1 else ""


# ---------------------------------------------------------------------------
# Verificari
# Toate verificarile de continut se aplica pe CORP, nu pe textul intreg -
# altfel "Cu stima," ar fi numarata ca propozitie si salutul (care contine
# numele raportorului) ar strica verificarile de limba.
# ---------------------------------------------------------------------------


def check(case: Case, text: str) -> dict[str, bool]:
    """Fiecare cheie e o verificare. True = trecut."""
    greeting, body, closing = split_email(text)
    c: dict[str, bool] = {}

    # --- structura de email ---
    c["are_salut"] = bool(greeting)
    c["are_corp"] = bool(body)
    c["are_incheiere"] = bool(closing)
    c["fara_semnatura"] = not PLACEHOLDER.search(text)

    prenume = first_name(case.reporter)
    nume = last_name(case.reporter)
    c["salut_cu_prenume"] = prenume.lower() in greeting.lower() if greeting else False
    c["fara_nume_de_familie"] = (
        (nume.lower() not in greeting.lower()) if (nume and greeting) else True
    )

    # --- limba ---
    c["diacritice"] = bool(CORRECT_DIACRITICS & set(body))
    c["fara_cedila"] = not (WRONG_CEDILLA & set(body))
    c["fara_engleza"] = not ENGLISH_LEAK.search(body)
    c["fara_calcuri"] = not CALQUES.search(body)
    c["adresare_formala"] = bool(re.search(r"\b(dumneavoastr[ăa]|v[ăa]|a[țt]i)\b", body, re.I))
    c["fara_tutuire"] = not re.search(
        r"\b(t[ăa]u|tine|[țt]i-|iti|îți|ai raportat|ai primit)\b", body, re.I
    )

    # --- forma ---
    c["min_3_propozitii"] = count_sentences(body) >= 3
    c["max_4_propozitii"] = count_sentences(body) <= 4
    c["fara_liste"] = not LIST_LINE.search(body)

    # --- per categorie ---
    if case.category == "SIMULATION":
        c["nu_dezvaluie_simularea"] = not LEAKS_SIMULATION.search(body)
        c["nu_da_verdict"] = not VERDICT_LEAK.search(body)
        c["promite_analiza"] = bool(ANALYSIS_PROMISE.search(body))

    elif case.category == "MALICIOUS":
        c["multumeste"] = bool(THANKS.search(body))
        c["confirma_pericolul"] = bool(DANGER.search(body))
        c["cere_stergerea"] = bool(DELETE_ASK.search(body))
        c["intreaba_de_click"] = bool(CLICK_Q.search(body))
        c["intrebarea_e_ultima"] = body.rstrip().endswith("?")

    elif case.category == "SPAM":
        c["multumeste"] = bool(THANKS.search(body))
        c["linisteste"] = bool(CALM.search(body))
        # Cazul din corpus are buton de dezabonare, iar exemplul din prompt
        # recomanda blocarea. Daca modelul copiaza exemplul, pica aici.
        if "dezabonare" in " ".join(case.evidence).lower():
            c["alege_dezabonarea"] = bool(UNSUB.search(body))
        else:
            c["alege_blocarea"] = bool(BLOCK.search(body))

    elif case.category == "LEGITIMATE":
        c["multumeste"] = bool(THANKS.search(body))
        c["confirma_ca_a_facut_bine"] = bool(GOOD_CALL.search(body))
        c["fara_repros"] = not BLAME.search(body)
        c["fara_intrebare"] = not body.rstrip().endswith("?")

    return c


# ---------------------------------------------------------------------------
# Generare
# ---------------------------------------------------------------------------


@dataclass
class Result:
    text: str
    seconds: float
    checks: dict[str, bool] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return all(self.checks.values())

    @property
    def failed_checks(self) -> list[str]:
        return [k for k, v in self.checks.items() if not v]


def build_client(model: str, args: argparse.Namespace) -> LLMClient:
    """Clientul de PRODUCTIE, nu unul scris pentru evaluare.

    Daca masuram cu alt cod decat cel care ruleaza pe bune, masuram altceva:
    alt timeout, alt num_predict, alt tratament al modelelor care "gandesc".
    `LLMSettings` valideaza si aici ca adresa e pe loopback.
    """
    settings = LLMSettings(
        enabled=True,
        api=args.api,
        base_url=args.base_url,
        model=model,
        temperature=args.temperature,
        timeout_seconds=args.timeout,
    )
    client = build_llm_client(settings)
    assert client is not None  # enabled=True, deci nu poate fi None
    return client


def generate(client: LLMClient, case: Case, temperature: float) -> Result:
    start = time.perf_counter()
    text = client.generate(
        system_prompt=SYSTEM_PROMPTS[case.category],
        prompt=case.user_prompt(),
        temperature=temperature,
    )
    elapsed = time.perf_counter() - start

    if DEBUG:
        print(f"    [debug] {elapsed:.1f}s raw={text[:160]!r}")
    return Result(text=text, seconds=elapsed, checks=check(case, text))


def baseline() -> None:
    """Evalueaza template-urile statice. Sunt reperul: scrise de om, deci 100%.

    Daca un model nu se apropie de reper, template-ul static e raspunsul corect
    pentru categoria aia - ceea ce arhitectura permite explicit.
    """
    print(f"\n{'=' * 70}\nBASELINE: template-uri statice\n{'=' * 70}")
    for case in CASES:
        text = STATIC_TEMPLATES[case.category].format(prenume=first_name(case.reporter))
        r = Result(text=text, seconds=0.0, checks=check(case, text))
        print(f"  [{'OK ' if r.passed else 'PICA'}] {case.category:12} {' '.join(r.failed_checks)}")


# ---------------------------------------------------------------------------
# Raport
# ---------------------------------------------------------------------------


def main() -> int:
    # Implicit: exact ce e configurat pentru productie. Nu vrei sa alegi un model
    # dupa o masuratoare facuta pe alt runtime decat cel care va rula.
    cfg = get_settings().llm

    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default=cfg.model, help=f"implicit: {cfg.model}")
    ap.add_argument("--api", choices=["ollama", "openai"], default=cfg.api)
    ap.add_argument("--base-url", default=cfg.base_url, help=f"implicit: {cfg.base_url}")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--temperature", type=float, default=0.2)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--out", default="")
    ap.add_argument("--baseline", action="store_true", help="doar template-urile statice")
    args = ap.parse_args()

    if args.baseline:
        baseline()
        return 0

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    print(f"Server: {args.base_url} (API {args.api})")
    report: list[str] = [
        "# Evaluare modele - drafter RO\n\n",
        f"Rulari per caz: {args.runs} | temperatura: {args.temperature}\n",
    ]
    summary: list[tuple[str, float, float, float, dict[str, int]]] = []

    for model in models:
        print(f"\n{'=' * 70}\nMODEL: {model}\n{'=' * 70}")
        report.append(f"\n## {model}\n")
        client = build_client(model, args)
        # O proba inainte, ca sa nu astepti patru timeout-uri ca sa afli ca serverul
        # nu ruleaza sau ca modelul se numeste altfel decat crezi.
        if not client.available():
            print(f"  {args.base_url} nu raspunde sau nu serveste modelul {model}.")
            print("  Porneste serverul, sau verifica numele exact al modelului.")
            return 1
        results: list[Result] = []
        per_case: dict[str, list[Result]] = {}

        for case in CASES:
            print(f"\n--- {case.category} ---")
            report.append(f"\n### {case.category}\n")
            per_case[case.category] = []
            for i in range(args.runs):
                try:
                    r = generate(client, case, args.temperature)
                except OllamaUnavailable as e:
                    print(f"  EROARE de la serverul de model: {e}")
                    return 1
                results.append(r)
                per_case[case.category].append(r)
                print(
                    f"  [{'OK ' if r.passed else 'PICA'}] {r.seconds:5.1f}s  "
                    f"{' '.join(r.failed_checks)}"
                )
                print("    " + r.text.replace("\n", "\n    "))
                if i == 0:
                    report.append(f"```\n{r.text}\n```\n")
                    if r.failed_checks:
                        report.append(f"Picate: {', '.join(r.failed_checks)}\n")

        # verificarile care pica cel mai des, ca sa stii unde sa intervii
        fails: dict[str, int] = {}
        for r in results:
            for k in r.failed_checks:
                fails[k] = fails.get(k, 0) + 1

        rate = sum(1 for r in results if r.passed) / len(results) * 100
        times = [r.seconds for r in results]
        # primul apel din fiecare categorie include incarcarea modelului in RAM
        warm = [r.seconds for rs in per_case.values() for r in rs[1:]] or times
        summary.append((model, rate, statistics.mean(warm), max(warm), fails))

        print(
            f"\n>>> {model}: {rate:.0f}% rulari complet corecte | "
            f"cald: media {statistics.mean(warm):.1f}s, maxim {max(warm):.1f}s"
        )
        if fails:
            print(
                "    cele mai frecvente esecuri: "
                + ", ".join(f"{k}({v})" for k, v in sorted(fails.items(), key=lambda x: -x[1])[:5])
            )

    print(f"\n{'=' * 70}\nSUMAR\n{'=' * 70}")
    print(f"{'model':<26}{'corecte':>10}{'media':>9}{'maxim':>9}")
    report.append(
        "\n## Sumar\n\n"
        "| Model | Rulari corecte | Timp mediu (cald) | Timp maxim | Esecuri frecvente |\n"
        "|---|---|---|---|---|\n"
    )
    for model, rate, avg, mx, fails in summary:
        print(f"{model:<26}{rate:>9.0f}%{avg:>8.1f}s{mx:>8.1f}s")
        top = ", ".join(f"{k} ({v})" for k, v in sorted(fails.items(), key=lambda x: -x[1])[:3])
        report.append(f"| {model} | {rate:.0f}% | {avg:.1f}s | {mx:.1f}s | {top or '-'} |\n")

    over = [m for m, _, _, mx, _ in summary if mx > 30]
    if over:
        print(f"\nATENTIE: peste 30s chiar si la cald: {', '.join(over)}")

    if args.out:
        Path(args.out).write_text("".join(report), encoding="utf-8")
        print(f"\nRaport scris in {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
