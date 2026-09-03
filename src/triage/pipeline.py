"""Ingestia: de la .eml brut la un rand in baza de date.

Un singur drum, folosit si de CLI, si de dashboard, si de poll-ul IMAP. Fiecare
pas isi scrie rezultatul in baza de date, deci pasii de dupa nu depind de cei
dinainte sa mai fie in memorie.

Ce inseamna asta in practica, pe cele trei promisiuni din sectiunea 3:

- Ollama picat: `generate_draft` cade pe template static, verdictul e deja
  scris. Un mail nu se pierde.
- Dashboard oprit: ingestia scrie in baza de date fara sa stie de el.
- Bug in drafter: exceptia e prinsa per mail, raportul se salveaza cu draft gol
  si status NEW, iar restul cozii continua.

Tot ce provine din mail e DEFANGED inainte de a fi scris. Criteriul 8.2 cere
zero URL-uri clicabile in baza de date sau in output, iar baza de date e locul
cel mai usor de uitat.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from triage.analyzer import analyze, score_of
from triage.db import Report, save_report, session
from triage.defang import defang
from triage.drafter import generate_draft
from triage.fetcher import fetch_from_corpus, save_raw_eml
from triage.llm import build_llm_client
from triage.parser import ParsedEmail, parse_report
from triage.settings import Settings, get_settings

logger = logging.getLogger(__name__)


@dataclass
class IngestResult:
    ingested: int = 0
    skipped: int = 0
    failed: int = 0
    report_ids: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return (
            f"{self.ingested} noi, {self.skipped} deja existente, {self.failed} esuate"
        )


def _evidence_rows(analysis: Any) -> list[dict[str, str]]:
    return [
        {
            "code": ev.code,
            "severity": str(ev.severity),
            "description": ev.description,
            "detail": ev.detail,
        }
        for ev in analysis.evidence
    ]


def _headers_row(parsed: ParsedEmail) -> dict[str, str]:
    return {
        "from": defang(parsed.from_address) or "-",
        "display_name": defang(parsed.from_display_name) or "-",
        "reply_to": defang(parsed.reply_to) or "-",
        "return_path": defang(parsed.return_path) or "-",
        "auth_results": defang(parsed.auth_results) or "-",
        "message_id": defang(parsed.message_id) or "-",
    }


def ingest_bytes(
    raw: bytes,
    *,
    source: str = "corpus",
    source_ref: str = "",
    raw_eml_path: str = "",
    llm_client: Any = None,
    settings: Settings | None = None,
) -> Report | None:
    """Un mail, tot drumul. None daca era deja ingerat (idempotenta)."""
    cfg = settings if settings is not None else get_settings()
    eml_sha256 = hashlib.sha256(raw).hexdigest()

    parsed = parse_report(raw)
    analysis = analyze(parsed)
    draft = generate_draft(
        analysis,
        parsed.reporter_display_name or parsed.reporter_address or "Coleg",
        llm_client=llm_client,
        max_input_chars=cfg.llm.max_input_chars,
    )

    with session() as s:
        return save_report(
            s,
            eml_sha256=eml_sha256,
            message_id=parsed.message_id,
            source=source,
            source_ref=source_ref,
            raw_eml_path=raw_eml_path,
            received_at=parsed.sent_at,
            reporter=defang(parsed.reporter_display_name or parsed.reporter_address) or "Necunoscut",
            subject=defang(parsed.subject) or "(Fără subiect)",
            from_address=defang(parsed.from_address) or "Necunoscut",
            report_kind=str(parsed.report_kind),
            verdict=str(analysis.verdict),
            confidence=analysis.confidence,
            score=score_of(list(analysis.evidence)),
            evidence=_evidence_rows(analysis),
            headers=_headers_row(parsed),
            defanged_urls=[defang(url) for url in parsed.urls],
            attachments=[
                {
                    "filename": att.filename,
                    "sha256": att.sha256,
                    "mime_type": att.mime_type,
                    "size": att.size,
                    "encrypted_archive": att.encrypted_archive,
                }
                for att in parsed.attachments
            ],
            body_text=defang(parsed.body_text),
            draft=draft.text,
            draft_source=draft.source,
        )


def ingest_file(path: Path, *, llm_client: Any = None, settings: Settings | None = None) -> Report | None:
    return ingest_bytes(
        path.read_bytes(),
        source="corpus",
        source_ref=path.name,
        raw_eml_path=str(path),
        llm_client=llm_client,
        settings=settings,
    )


def ingest_corpus(
    corpus_dir: Path | None = None, *, settings: Settings | None = None
) -> IngestResult:
    """Toate .eml-urile din corpus. Rulabila de oricate ori: nu duplica nimic."""
    cfg = settings if settings is not None else get_settings()
    directory = corpus_dir if corpus_dir is not None else default_corpus_dir()
    llm_client = build_llm_client(cfg.llm)
    result = IngestResult()

    for path in fetch_from_corpus(directory):
        try:
            report = ingest_file(path, llm_client=llm_client, settings=cfg)
        except Exception as err:  # un mail stricat nu opreste coada (8.3)
            logger.exception("Ingestie esuata pentru %s", path)
            result.failed += 1
            result.errors.append(f"{path.name}: {err}")
            continue
        if report is None:
            result.skipped += 1
        else:
            result.ingested += 1
            result.report_ids.append(report.id)

    return result


def ingest_imap(*, settings: Settings | None = None) -> IngestResult:
    """Un ciclu de poll IMAP, cu salvarea .eml-ului brut pe disc."""
    from triage.fetcher import fetch_from_imap  # import tarziu: imaplib e greu

    cfg = settings if settings is not None else get_settings()
    llm_client = build_llm_client(cfg.llm)
    result = IngestResult()

    for message in fetch_from_imap(cfg.imap):
        try:
            destination = cfg.paths.raw_eml_dir / f"{message.sha256}.eml"
            if not destination.exists():
                save_raw_eml(message.raw, destination)
            report = ingest_bytes(
                message.raw,
                source="imap",
                source_ref=message.uid,
                raw_eml_path=str(destination),
                llm_client=llm_client,
                settings=cfg,
            )
        except Exception as err:
            logger.exception("Ingestie esuata pentru mesajul IMAP %s", message.uid)
            result.failed += 1
            result.errors.append(f"{message.uid}: {err}")
            continue
        if report is None:
            result.skipped += 1
        else:
            result.ingested += 1
            result.report_ids.append(report.id)

    return result


def ingest_once(settings: Settings | None = None) -> IngestResult:
    """Un ciclu de ingestie din sursa configurata."""
    cfg = settings if settings is not None else get_settings()
    return ingest_imap(settings=cfg) if cfg.source == "imap" else ingest_corpus(settings=cfg)


def default_corpus_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "corpus" / "eml"
