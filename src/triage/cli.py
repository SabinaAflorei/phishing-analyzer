"""Interfata in linia de comanda.

    triage ingest              # un ciclu din sursa configurata
    triage poll                # ingestie la interval, pana la Ctrl+C
    triage list --status NEW   # ce e in coada
    triage show 3              # un raport din baza de date
    triage check mail.eml      # analizeaza un .eml fara sa il salveze

`check` e singura comanda care nu atinge baza de date: e pentru cand vrei sa
vezi repede ce zice analizorul despre un fisier, fara sa il bagi in coada.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

from triage import db
from triage.analyzer import analyze, score_of
from triage.db import dump_json, session, to_dict
from triage.defang import defang
from triage.drafter import generate_draft
from triage.llm import build_llm_client
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
    parsed = parse_report(path.read_bytes())
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
    p_show.set_defaults(func=cmd_show)

    p_check = sub.add_parser("check", help="analizeaza un .eml fara sa il salveze")
    p_check.add_argument("eml_file", type=Path)
    p_check.add_argument("--json", action="store_true")
    p_check.add_argument("--llm", action="store_true", help="cere ciorna de la Ollama")
    p_check.set_defaults(func=cmd_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
