"""Interfata in linia de comanda.

    triage ingest              # un ciclu din sursa configurata
    triage poll                # ingestie la interval, pana la Ctrl+C
    triage list --status NEW   # ce e in coada
    triage show 3              # un raport din baza de date
    triage show 3 --draft      # doar ciorna, ca sa o poti trece prin pipe
    triage stats               # metricile de calitate din 8.4
    triage check mail.eml      # analizeaza un .eml sau .msg fara sa il salveze

`check` e singura comanda care nu atinge baza de date: e pentru cand vrei sa
vezi repede ce zice analizorul despre un fisier, fara sa il bagi in coada.
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

from triage import db
from triage.analyzer import analyze, score_of
from triage.db import dump_json, quality_stats, session, to_dict
from triage.defang import defang
from triage.drafter import generate_draft
from triage.llm import build_llm_client
from triage.msg_convert import MsgConversionUnavailable, looks_like_msg, msg_bytes_to_eml
from triage.parser import parse_report
from triage.pipeline import ingest_once
from triage.settings import get_settings

logger = logging.getLogger(__name__)

RULER = "=" * 68


def cmd_ingest(_: argparse.Namespace) -> int:
    result = ingest_once()
    print(f"Ingestie: {result}")
    for error in result.errors:
        print(f"  eroare: {error}", file=sys.stderr)
    return 1 if result.failed else 0


def cmd_poll(args: argparse.Namespace) -> int:
    """Poll la interval configurabil, implicit 5 minute (sectiunea 6.1)."""
    interval = args.interval or get_settings().poll_interval_seconds
    print(f"Poll la fiecare {interval}s. Ctrl+C pentru oprire.")
    try:
        while True:
            try:
                print(f"  {time.strftime('%H:%M:%S')}  {ingest_once()}")
            except Exception as err:  # un ciclu esuat nu opreste bucla
                logger.exception("Ciclu de ingestie esuat")
                print(f"  ciclu esuat: {err}", file=sys.stderr)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nOprit.")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    with session() as s:
        reports = db.list_reports(s, status=args.status, verdict=args.verdict)
        rows = [to_dict(r) for r in reports]

    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0

    if not rows:
        print("Coada e goala. Ruleaza `triage ingest`.")
        return 0

    print(f"{'ID':>4}  {'VERDICT':<13} {'INCR':>5}  {'STATUS':<11} SUBIECT")
    for row in rows:
        subject = row["subject"][:44]
        print(
            f"{row['id']:>4}  {row['verdict']:<13} {row['confidence']:>5.2f}  "
            f"{row['status']:<11} {subject}"
        )
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    with session() as s:
        report = db.get_report(s, args.report_id)
        if report is None:
            print(f"Nu exista raportul {args.report_id}.", file=sys.stderr)
            return 1
        if args.draft:
            # Doar textul, fara chenare: `triage show 3 --draft | clip` sau
            # `| xclip` pune ciorna direct in clipboard. Analistul o lipeste in
            # clientul lui de mail - sistemul tot nu trimite nimic.
            print(to_dict(report)["draft"])
            return 0
        if args.json:
            print(dump_json(report))
            return 0
        data = to_dict(report)
        evidence = report.evidence

    _print_report(data, evidence)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Analizeaza un .eml fara sa il salveze nicaieri."""
    path: Path = args.eml_file
    if not path.is_file():
        print(f"Eroare: fisierul '{path}' nu exista.", file=sys.stderr)
        return 1

    settings = get_settings()
    raw = path.read_bytes()

    # Un .msg salvat din Outlook se converteste pe loc, ca analizorul sa vada
    # mereu RFC822. Recunoasterea e pe CONTINUT (semnatura OLE), nu pe extensie:
    # extensia o alege cel care trimite fisierul, deci nu e o dovada.
    #
    # Orice ALTCEVA trece neatins la parser, inclusiv gunoi. Spre deosebire de
    # dropzone-ul din dashboard - unde cineva chiar poate trage din greseala o
    # poza - aici operatorul a numit fisierul explicit, iar criteriul 8.3 cere ca
    # un mail malformat sa fie analizat, nu respins.
    if looks_like_msg(raw):
        try:
            raw = msg_bytes_to_eml(raw)
        except MsgConversionUnavailable as err:
            print(f"Eroare: {err}", file=sys.stderr)
            return 1

    parsed = parse_report(raw)
    analysis = analyze(parsed)
    draft = generate_draft(
        analysis,
        parsed.reporter_display_name or parsed.reporter_address or "Coleg",
        llm_client=build_llm_client(settings.llm) if args.llm else None,
        max_input_chars=settings.llm.max_input_chars,
    )

    data: dict[str, Any] = {
        "file": path.name,
        "subject": defang(parsed.subject),
        "reporter": defang(parsed.reporter_address),
        "from_address": defang(parsed.from_address),
        "report_kind": str(parsed.report_kind),
        "verdict": analysis.verdict.value,
        "confidence": analysis.confidence,
        "score": score_of(list(analysis.evidence)),
        "defanged_urls": [defang(url) for url in parsed.urls],
        "draft": draft.text,
        "draft_source": draft.source,
    }
    evidence = [
        {
            "code": ev.code,
            "severity": str(ev.severity),
            "description": ev.description,
            "detail": ev.detail,
        }
        for ev in analysis.evidence
    ]

    if args.json:
        print(json.dumps({**data, "evidence": evidence}, indent=2, ensure_ascii=False))
    else:
        _print_report(data, evidence)
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    """Metricile de calitate din 8.4, din baza de date.

    Existau deja, calculate de `quality_stats`, dar se vedeau doar din browser.
    Matricea de corectii e informatia care spune unde sa te uiti: care verdict
    automat e cel mai des schimbat de analist, si in ce. Ponderile din
    SIGNAL_WEIGHT se calibreaza dupa ea, nu dupa intuitie.
    """
    with session() as s:
        stats = quality_stats(s)

    if args.json:
        print(json.dumps(stats, indent=2, ensure_ascii=False))
        return 0

    if not stats["total_reports"]:
        print("Baza de date e goala. Ruleaza `triage ingest`.")
        return 0

    print(RULER)
    print("Calitate")
    print(RULER)
    print(f"Rapoarte:            {stats['total_reports']}")
    print(f"Ciorne trimise:      {stats['total_drafts_sent']}")
    print(f"Acceptate nemodif.:  {stats['unchanged_drafts']} ({stats['acceptance_rate']:.1f}%)")
    print(f"Verdicte corectate:  {stats['overrides_count']} ({stats['correction_rate']:.1f}%)")

    print("-" * 68)
    print("Distributia verdictelor:")
    for verdict, count in stats["verdict_distribution"].items():
        print(f"  {verdict:<14} {count:>4}")

    print("-" * 68)
    print("Pe status:")
    for status, count in stats["by_status"].items():
        print(f"  {status:<14} {count:>4}")

    print("-" * 68)
    matrix = stats["correction_matrix"]
    print("Matrice de corectii (automat -> corectat de analist):")
    if not matrix:
        print("  Niciun verdict corectat inca.")
    else:
        for auto, targets in matrix.items():
            for corrected, count in sorted(targets.items(), key=lambda kv: -kv[1]):
                print(f"  {auto:<14} -> {corrected:<14} {count:>4}")
    print(RULER)
    return 0


def _print_report(data: dict[str, Any], evidence: list[dict[str, str]]) -> None:
    print(RULER)
    print(f"{data.get('subject', '(fara subiect)')}")
    print(RULER)
    print(f"Expeditor:  {data.get('from_address', '-')}")
    print(f"Raportor:   {data.get('reporter', '-')}")
    print(
        f"Verdict:    {data['verdict']}  (incredere {data['confidence']:.2f}, "
        f"scor {data.get('score', 0):.2f})"
    )

    print("-" * 68)
    print("Dovezi:")
    for ev in evidence:
        print(f"  [{ev['severity']:<8}] {ev['code']}")
        print(f"             {ev['description']}")
        if ev.get("detail"):
            print(f"             {ev['detail']}")

    urls = data.get("defanged_urls") or []
    print("-" * 68)
    print(f"URL-uri dezamorsate ({len(urls)}):")
    for url in urls:
        print(f"  {url}")

    print("-" * 68)
    draft = data.get("draft") or ""
    source = data.get("draft_source", "")
    print(f"Ciorna de raspuns{f' ({source})' if source else ''}:")
    print(draft or "  (verdict NEEDS_REVIEW - nu se genereaza ciorna automata)")
    print(RULER)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triage",
        description="Asistent local de triaj pentru mail-uri de phishing raportate.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="log detaliat")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", help="un ciclu de ingestie din sursa configurata")
    p_ingest.set_defaults(func=cmd_ingest)

    p_poll = sub.add_parser("poll", help="ingestie la interval, pana la Ctrl+C")
    p_poll.add_argument("--interval", type=int, help="secunde (implicit: din settings.yaml)")
    p_poll.set_defaults(func=cmd_poll)

    p_list = sub.add_parser("list", help="rapoartele din coada")
    p_list.add_argument("--status", help="NEW / IN_PROGRESS / SENT / ESCALATED")
    p_list.add_argument(
        "--verdict", help="SIMULATION / MALICIOUS / SPAM / LEGITIMATE / NEEDS_REVIEW"
    )
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="un raport din baza de date")
    p_show.add_argument("report_id", type=int)
    p_show.add_argument("--json", action="store_true")
    p_show.add_argument("--draft", action="store_true", help="doar ciorna, fara chenare")
    p_show.set_defaults(func=cmd_show)

    p_stats = sub.add_parser("stats", help="metricile de calitate (8.4)")
    p_stats.add_argument("--json", action="store_true")
    p_stats.set_defaults(func=cmd_stats)

    p_check = sub.add_parser("check", help="analizeaza un .eml sau .msg fara sa il salveze")
    p_check.add_argument("eml_file", type=Path, help="fisier .eml sau .msg")
    p_check.add_argument("--json", action="store_true")
    p_check.add_argument("--llm", action="store_true", help="cere ciorna de la Ollama")
    p_check.set_defaults(func=cmd_check)

    return parser


def _force_utf8_output() -> None:
    """Tot ce scrie CLI-ul e in romana, cu diacritice.

    Pe Windows, stdout-ul implicit e cp1252, care nu are 'ă'. Orice comanda care
    tiparea un verdict, o dovada sau o ciorna cadea cu UnicodeEncodeError inainte
    sa termine de scris - `triage show`, `triage check` si `triage list`
    deopotriva. Nu e o optiune de configurare: fisierul sursa e UTF-8, dovezile
    sunt UTF-8, deci si iesirea trebuie sa fie.
    """
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
