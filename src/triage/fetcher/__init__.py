"""IMAP read-only + sursă statică de .eml. Nu șterge și nu mută mesaje."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any
import time
import imaplib

from triage.db import get_session, report_id_for, upsert_report
from triage.secure_files import save_secure_file
from triage.settings import get_settings, get_ollama_client, llm_enabled
from triage.analyzer import analyze
from triage.defang import defang
from triage.drafter import build_draft
from triage.parser import parse_report

logger = logging.getLogger(__name__)


def fetch_from_corpus(corpus_dir: Path) -> list[Path]:
    """Sursă offline pentru dezvoltare și teste.

    Caută toate fișierele de mail (.eml / .EML) din directorul corpus.
    Aruncă excepții dacă directorul nu există sau nu este un director valid.
    """
    if not corpus_dir.exists() or not corpus_dir.is_dir():
        logger.warning("Directorul corpus specificat nu există sau nu este director: %s", corpus_dir)
        return []

    eml_files = [
        p for p in corpus_dir.iterdir()
        if p.is_file() and p.suffix.lower() == ".eml"
    ]

    if not eml_files:
        logger.warning("Nu s-au găsit fișiere .eml în directorul: %s", corpus_dir)

    return sorted(eml_files)


def save_raw_eml(content: bytes, destination_path: Path) -> Path:
    """Salvează conținutul brut al unui e-mail pe disc cu permisiuni restrictive ."""
    save_secure_file(destination_path, content)
    return destination_path

def _connect_imap_with_retry(
    server: str, port: int, user: str, password: str,
    max_attempts: int, backoff_seconds: float,
) -> "imaplib.IMAP4_SSL":
    """Conectare + login IMAP cu retry si backoff exponential.
    Criteriul 8.3: mailbox indisponibil -> retry, fara pierdere de mesaje.
    Nu se sterge/marcheaza nimic pana la o conexiune reusita, deci un
    esec aici nu poate pierde mesaje - pur si simplu nu se proceseaza
    nimic in acel ciclu de poll, si se reincearca la urmatorul."""
    last_error: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            mail = imaplib.IMAP4_SSL(server, port)
            mail.login(user, password)
            if attempt > 1:
                logger.info(
                    "Conectare IMAP reusita la incercarea %d/%d.",
                    attempt, max_attempts,
                )
            return mail
        except (imaplib.IMAP4.error, OSError) as err:
            last_error = err
            if attempt < max_attempts:
                wait = backoff_seconds * (2 ** (attempt - 1))
                logger.warning(
                    "Conectare IMAP esuata (incercarea %d/%d): %s. Reincerc in %.0fs.",
                    attempt, max_attempts, err, wait,
                )
                time.sleep(wait)
            else:
                logger.error(
                    "Conectare IMAP esuata definitiv dupa %d incercari: %s",
                    max_attempts, err,
                )

    assert last_error is not None
    raise last_error

def fetch_from_imap() -> list[Path]:
    """Poll read-only IMAP.
    Preia mesaje neprocesate, le salvează securizat, le introduce în DB
    fără să le șteargă de pe server, asigurând idempotența.
    """

    settings = get_settings()
    downloaded_paths: list[Path] = []

    server = os.getenv("TRIAGE_IMAP_SERVER", getattr(settings, "imap_server", "localhost"))
    port = int(os.getenv("TRIAGE_IMAP_PORT", getattr(settings, "imap_port", 993)))
    user = os.getenv("TRIAGE_IMAP_USER", getattr(settings, "imap_user", ""))
    password = os.getenv("TRIAGE_IMAP_PASSWORD", getattr(settings, "imap_password", ""))
    storage_dir = Path(settings.paths.raw_eml_dir)

    if not user or not password:
        logger.debug("Credențialele IMAP nu sunt configurate. Se sare peste poll-ul IMAP.")
        return downloaded_paths

    try:
        mail = _connect_imap_with_retry(
            server=server,
            port=port,
            user=user,
            password=password,
            max_attempts=settings.fetcher.imap_retry_attempts,
            backoff_seconds=settings.fetcher.imap_retry_backoff_seconds,
        )

        mail.select("INBOX", readonly=True)

        status, response = mail.search(None, "UNSEEN")
        if status != "OK":
            logger.warning("Eroare la căutarea mesajelor IMAP: %s", status)
            mail.logout()
            return downloaded_paths

        session = get_session()
        try:
            for e_id in response[0].split():
                status, data = mail.fetch(e_id, "(RFC822)")
                if status != "OK":
                    continue

                for response_part in data:
                    if isinstance(response_part, tuple):
                        raw_bytes = response_part[1]

                        # Generare ID / Hash stabil pentru idempotență
                        report_id = report_id_for(raw_bytes)

                        # Salvare fișier .eml brut cu permisiuni restrictive (0o600)
                        filename = f"{report_id}.eml"
                        dest_path = storage_dir / filename
                        save_secure_file(dest_path, raw_bytes)
                        downloaded_paths.append(dest_path)

                        # Procesare prin pipeline și scriere în baza de date
                        try:
                            report_data = _process_eml_bytes(raw_bytes, filename)
                            report_data["id"] = report_id
                            upsert_report(session, report_data)
                        except Exception as e:
                            logger.error("Eroare la procesarea mesajului IMAP ID %s: %s", e_id, e)

        finally:
            session.close()

        mail.logout()
    except Exception as e:
        logger.error("Eroare de conexiune sau comunicare cu serverul IMAP: %s", e)

    return downloaded_paths

def _process_eml_bytes(raw_bytes: bytes, file_name: str) -> dict[str, Any]:
    """Parsează, analizează și pregătește dicționarul de date pentru DB 
    pornind de la bytes-ii unui e-mail brut (evită importul circular din ingest).
    """

    report_id = report_id_for(raw_bytes)
    parsed = parse_report(raw_bytes)
    analysis = analyze(parsed)
    defanged_urls = [defang(u) for u in parsed.urls]
    reporter_name = parsed.from_address.split("<")[0].strip() or "Coleg"
    
    draft = build_draft(
        analysis=analysis, 
        reporter_name=reporter_name, 
        llm_client=get_ollama_client() if llm_enabled() else None
    )

    return {
        "id": report_id,
        "file_name": file_name,
        "subject": parsed.subject or "(Fără subiect)",
        "from_address": parsed.from_address or "Necunoscut",
        "reporter": parsed.from_address or "Necunoscut",
        "verdict": analysis.verdict.value,
        "confidence": analysis.confidence,
        "evidence_json": json.dumps([
            f"{e.description} ({e.detail})" if e.detail else e.description
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
    }