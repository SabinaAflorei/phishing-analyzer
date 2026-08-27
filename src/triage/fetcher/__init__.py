"""IMAP read-only + sursa statica de .eml. Nu sterge si nu muta mesaje."""

from __future__ import annotations

from pathlib import Path


def fetch_from_corpus(corpus_dir: Path) -> list[Path]:
    """Sursa offline pentru dezvoltare si teste.
    
    Cauta toate fisierele de mail (.msg / .eml) din directorul corpus.
    """
    if not corpus_dir.exists() or not corpus_dir.is_dir():
        return []

    # Caută fișierele .msg și .eml din corpus și le sortează
    files = sorted(list(corpus_dir.glob("*.msg")) + list(corpus_dir.glob("*.eml")))
    return files


def fetch_from_imap() -> list[Path]:
    """Poll read-only. Marcheaza procesatele in DB, nu le sterge. Idempotent la restart."""
    # Stub offline pentru IMAP
    return []