"""Interfață în linia de comandă (CLI) pentru pipeline-ul de triaj phishing."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from triage.analyzer import analyze
from triage.defang import defang
from triage.drafter import build_draft
from triage.parser import parse_report


def process_eml(file_path: Path, output_json: bool = False) -> int:
    """Procesează un fișier .eml prin tot pipeline-ul de triaj."""
    if not file_path.exists():
        print(f"Eroare: Fișierul '{file_path}' nu există.", file=sys.stderr)
        return 1

    # 1. Parsare e-mail 
    raw_bytes = file_path.read_bytes()
    parsed_mail = parse_report(raw_bytes)

    # 2. Analiza si verdict
    analysis_result = analyze(parsed_mail)

    # 3. Sanitizare
    defanged_urls = [defang(url) for url in parsed_mail.urls]

    # 4. Generare Draft
    reporter_name = parsed_mail.from_address.split("<")[0].strip() or "Coleg"
    draft_text = build_draft(
        analysis=analysis_result,
        reporter_name=reporter_name,
    )

    #convertire obiecte pentru lizibilitate JSON
    evidence_list=[str(ev) for ev in analysis_result.evidence]
    # Structura rezultatului
    result = {
        "file": file_path.name,
        "subject": parsed_mail.subject,
        "from_address": parsed_mail.from_address,
        "verdict": analysis_result.verdict.value,
        "confidence": analysis_result.confidence,
        "evidence": evidence_list,
        "defanged_urls": defanged_urls,
        "draft": draft_text,
    }

    if output_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("=" * 60)
        print(f"RAPORT TRIAJ PHISHING: {result['file']}")
        print("=" * 60)
        print(f"Subiect:    {parsed_mail.subject}")
        print(f"Expeditor:  {parsed_mail.from_address}")
        print(f"Verdict:    {analysis_result.verdict.value} (Încredere: {analysis_result.confidence})")
        print("-" * 60)
        print("Probe (Evidence):")
        for ev in analysis_result.evidence:
            print(f"  - {ev}")
        print("-" * 60)
        print("URL-uri dezamorsate (Defanged):")
        for url in defanged_urls:
            print(f"  - {url}")
        print("-" * 60)
        print("Ciornă răspuns (Draft):")
        print(draft_text)
        print("=" * 60)

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Instrument CLI pentru procesarea și triajul e-mailurilor de phishing (.eml)."
    )
    parser.add_argument(
        "eml_file",
        type=Path,
        help="Calea către fișierul .eml de analizat",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Afișează rezultatul în format JSON",
    )

    args = parser.parse_args()
    sys.exit(process_eml(args.eml_file, output_json=args.json))


if __name__ == "__main__":
    main()