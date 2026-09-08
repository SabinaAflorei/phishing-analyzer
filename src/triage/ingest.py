"""Ingestie: fetcher -> parser -> analyzer -> drafter -> DB.
Idempotent: id-ul e hash-ul continutului, deci
reprocesarea aceluiasi fisier face UPSERT, nu duplica randul."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from triage.analyzer import analyze
from triage.db import get_session, init_db, report_id_for, upsert_report
from triage.defang import defang
from triage.drafter import build_draft
from triage.fetcher import fetch_from_corpus
from triage.parser import parse_report
from triage.settings import get_ollama_client, llm_enabled

logger = logging.getLogger(__name__)


def ingest_corpus(corpus_dir: Path) -> int:
    """Proceseaza toate .eml din corpus_dir. Returneaza numarul procesat cu succes."""
    init_db()
    session = get_session()
    processed = 0

    for eml_path in fetch_from_corpus(corpus_dir):
        try:
            raw_bytes = eml_path.read_bytes()
            report_id = report_id_for(raw_bytes)

            parsed = parse_report(raw_bytes)
            analysis = analyze(parsed)
            defanged_urls = [defang(u) for u in parsed.urls]
            reporter_name = parsed.from_address.split("<")[0].strip() or "Coleg"
            draft = build_draft(analysis=analysis, reporter_name=reporter_name, llm_client=get_ollama_client() if llm_enabled() else None,)

            upsert_report(session, {
                "id": report_id,
                "file_name": eml_path.name,
                "subject": parsed.subject or "(Fără subiect)",
                "from_address": parsed.from_address or "Necunoscut",
                "reporter": parsed.from_address or "Necunoscut",
                "verdict": analysis.verdict.value,
                "confidence": analysis.confidence,
                "evidence_json": json.dumps([
                    {
                        "code": e.code,
                        "severity": e.severity.value,
                        "description": e.description,
                        "detail": e.detail,
                    }
                    for e in analysis.evidence
                ]),
                "defanged_urls_json": json.dumps(defanged_urls),
                "body_text": defang(parsed.body_text),
                "draft": draft,
                "attachments_json": json.dumps([
                    {"filename": a.filename, "sha256": a.sha256,
                     "mime_type": a.mime_type, "size": a.size}
                    for a in parsed.attachments
                ]),
                "headers_json": json.dumps({
                    "from": parsed.from_address or "-",
                    "reply_to": parsed.reply_to or "-",
                    "return_path": parsed.return_path or "-",
                    "auth_results": parsed.auth_results or "-",
                }),
            })
            processed += 1
        except Exception:
            logger.exception("Eroare la procesarea %s", eml_path)
            continue

    session.close()
    return processed