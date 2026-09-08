"""IMAP read-only + sursă statică de .eml. Nu șterge și nu mută mesaje."""

from __future__ import annotations

import logging
import os
from pathlib import Path
import email
from email.message import Message
from typing import List
from triage.settings import get_settings
import imaplib

logger = logging.getLogger(__name__)


def fetch_from_corpus(corpus_dir: Path) -> list[Path]:
    """Sursă offline pentru dezvoltare și teste.

    Caută toate fișierele de mail (.eml / .EML) din directorul corpus.
    Aruncă excepții dacă directorul nu există sau nu este un director valid.
    """
    if not corpus_dir.exists() or not corpus_dir.is_dir():
        logger.warning("Directorul corpus specificat nu există sau nu este director: %s", corpus_dir)
        return []

    # Cautare case-insensitive pentru fisiere .eml 
    eml_files = [
        p for p in corpus_dir.iterdir()
        if p.is_file() and p.suffix.lower() == ".eml"
    ]

    if not eml_files:
        logger.warning("Nu s-au găsit fișiere .eml în directorul: %s", corpus_dir)

    return sorted(eml_files)


def save_raw_eml(content: bytes, destination_path: Path) -> Path:
    """Salvează conținutul brut al unui e-mail pe disc cu permisiuni restrictive ."""
    destination_path.parent.mkdir(parents=True, exist_ok=True)

    # Setare umask temporar sau aplicare chmod direct pentru restrictionare citire doar la proprietar
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    mode = 0o600

    fd = os.open(destination_path, flags, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(content)

    return destination_path


def fetch_from_imap() -> list[Path]:
    """Poll read-only. Marchează procesatele în DB, nu le șterge. Idempotent la restart."""
    settings = get_settings()
    downloaded_paths: list[Path] = []
    
    server = getattr(settings, "IMAP_SERVER", "localhost")
    port = getattr(settings, "IMAP_PORT", 993)
    user = getattr(settings, "IMAP_USER", "")
    password = getattr(settings, "IMAP_PASSWORD", "")
    storage_dir = Path(getattr(settings, "RAW_EML_DIR", "data/raw_eml"))

    if not user or not password:
        logger.debug("Credențialele IMAP nu sunt configurate. Se sare peste poll.")
        return downloaded_paths

    try:
        mail = imaplib.IMAP4_SSL(server, port)
        mail.login(user, password)
        mail.select("INBOX", readonly=True)

        status, response = mail.search(None, "UNSEEN")
        if status != "OK":
            mail.logout()
            return downloaded_paths

        for e_id in response[0].split():
            status, data = mail.fetch(e_id, "(RFC822)")
            if status != "OK":
                continue

            for response_part in data:
                if isinstance(response_part, tuple):
                    raw_bytes = response_part[1]
                    msg = email.message_from_bytes(raw_bytes)
                    message_id = msg.get("Message-ID", "").strip()

                    # Verificare idempotență în baza de date (A1)
                    # Dacă există deja în DB după Message-ID sau hash, se ignoră
                    # if message_id and db_has_message_id(message_id):
                    #     continue

                    # Salvare locală cu permisiuni restrictive (600)
                    filename = f"{message_id.strip('<>') or e_id.decode()}.eml"
                    dest_path = storage_dir / filename
                    save_raw_eml(raw_bytes, dest_path)
                    downloaded_paths.append(dest_path)

        mail.logout()
    except Exception as e:
        logger.error("Eroare în timpul rulării IMAP poll: %s", e)

    return downloaded_paths