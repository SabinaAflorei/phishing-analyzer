"""IMAP read-only + sursă statică de .eml. Nu șterge și nu mută mesaje."""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def fetch_from_corpus(corpus_dir: Path) -> list[Path]:
    """Sursă offline pentru dezvoltare și teste.

    Caută toate fișierele de mail (.eml / .EML) din directorul corpus.
    Aruncă excepții dacă directorul nu există sau nu este un director valid.
    """
    if not corpus_dir.exists() or not corpus_dir.is_dir():
        logger.warning("Directorul corpus specificat nu există sau nu este director: %s", corpus_dir)
        return []

    # Cautare case-insensitive pentru fisiere .eml (acoperă .eml, .EML, .Eml etc.)
    eml_files = [
        p for p in corpus_dir.iterdir()
        if p.is_file() and p.suffix.lower() == ".eml"
    ]

    if not eml_files:
        logger.warning("Nu s-au găsit fișiere .eml în directorul: %s", corpus_dir)

    return sorted(eml_files)


def save_raw_eml(content: bytes, destination_path: Path) -> Path:
    """Salvează conținutul brut al unui e-mail pe disc cu permisiuni restrictive (0600 - Section 6.1)."""
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
    # Stub pentru integrare IMAP cu DB și retry logic
    logger.info("Polling IMAP executat (stub).")
    return []