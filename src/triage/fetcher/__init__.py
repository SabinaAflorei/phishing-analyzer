"""IMAP read-only + sursa statica de .eml. Nu sterge si nu muta mesaje."""

from __future__ import annotations

import hashlib
import imaplib
import logging
import os
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from triage.db import mark_excluded_from_backups
from triage.settings import ImapSettings

logger = logging.getLogger(__name__)


def fetch_from_corpus(corpus_dir: Path) -> list[Path]:
    """Sursa offline pentru dezvoltare si teste."""
    if not corpus_dir.exists() or not corpus_dir.is_dir():
        logger.warning("Directorul corpus nu exista sau nu e director: %s", corpus_dir)
        return []

    eml_files = [p for p in corpus_dir.iterdir() if p.is_file() and p.suffix.lower() == ".eml"]
    if not eml_files:
        logger.warning("Nu s-au gasit fisiere .eml in directorul: %s", corpus_dir)
    return sorted(eml_files)


def save_raw_eml(content: bytes, destination_path: Path) -> Path:
    """Salveaza .eml-ul brut cu permisiuni restrictive (sectiunea 4.5)."""
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(destination_path.parent, 0o700)  # noqa: PTH101 - chmod explicit pe Path existent
    mark_excluded_from_backups(destination_path.parent.parent)

    fd = os.open(destination_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(content)

    return destination_path


# ---------------------------------------------------------------------------
# IMAP
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ImapMessage:
    uid: str
    raw: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


class MailboxUnavailable(RuntimeError):
    """Mailbox-ul nu raspunde. Se reincearca; niciun mesaj nu se pierde."""


def _default_connect(imap: ImapSettings) -> Any:
    """Conexiune IMAPS. Parola vine din .env, niciodata din cod."""
    connection = imaplib.IMAP4_SSL(imap.host, imap.port)
    connection.login(imap.user, imap.app_password)
    return connection


def fetch_from_imap(
    imap: ImapSettings,
    *,
    connect: Callable[[ImapSettings], Any] | None = None,
    retries: int = 3,
    backoff_seconds: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
) -> list[ImapMessage]:
    """Un poll read-only. Nu sterge, nu muta si nu marcheaza nimic pe server.

    Evidenta a ce s-a procesat se tine in baza de date, pe hash-ul mesajului -
    nu pe flag-uri IMAP. Motivul e ca flag-urile sunt scriere pe mailbox-ul
    oamenilor, iar sectiunea 6.1 cere explicit sa nu atingem mesajele. Efectul
    secundar bun: o repornire sau un al doilea poll nu reproceseaza nimic,
    pentru ca `already_ingested` filtreaza inainte de scriere (criteriul I9).

    Mailbox indisponibil inseamna reincercare cu asteptare crescatoare, apoi
    MailboxUnavailable. Niciun mesaj nu se pierde: nimic nu s-a modificat pe
    server, deci urmatorul poll ia totul de la capat (criteriul 8.3).
    """
    if not imap.configured:
        logger.info(
            "IMAP neconfigurat (TRIAGE_IMAP_HOST / USER / APP_PASSWORD lipsesc). "
            "Nu se face poll. Sursa ramane corpusul offline."
        )
        return []

    opener = connect or _default_connect
    last_error: Exception | None = None

    for attempt in range(1, retries + 1):
        try:
            return _fetch_once(imap, opener)
        except (imaplib.IMAP4.error, OSError, EOFError) as err:
            last_error = err
            logger.warning("Mailbox indisponibil (incercarea %d/%d): %s", attempt, retries, err)
            if attempt < retries:
                sleep(backoff_seconds * (2 ** (attempt - 1)))

    raise MailboxUnavailable(
        f"Mailbox indisponibil dupa {retries} incercari: {last_error}"
    ) from last_error


def _fetch_once(imap: ImapSettings, opener: Callable[[ImapSettings], Any]) -> list[ImapMessage]:
    connection = opener(imap)
    try:
        # readonly=True e garantia ca nu se schimba nimic pe mailbox-ul real,
        # inclusiv flag-ul \Seen. Nu il scoate.
        status, _ = connection.select(imap.folder, readonly=True)
        if status != "OK":
            raise MailboxUnavailable(f"Nu se poate selecta folderul {imap.folder!r}")

        status, data = connection.search(None, "ALL")
        if status != "OK":
            raise MailboxUnavailable("Cautarea in mailbox a esuat")

        messages: list[ImapMessage] = []
        for uid in (data[0] or b"").split():
            status, payload = connection.fetch(uid, "(RFC822)")
            if status != "OK" or not payload:
                logger.warning("Mesajul %s nu a putut fi citit; se reia la urmatorul poll", uid)
                continue
            raw = _extract_rfc822(payload)
            if raw:
                messages.append(ImapMessage(uid=uid.decode("ascii", "replace"), raw=raw))
        return messages
    finally:
        for closer in (connection.close, connection.logout):
            # Inchiderea nu are voie sa mascheze mesajele deja citite.
            with suppress(Exception):
                closer()


def _extract_rfc822(payload: list[Any]) -> bytes:
    """imaplib intoarce o lista de tupluri; corpul e al doilea element."""
    for item in payload:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
            return item[1]
    return b""
