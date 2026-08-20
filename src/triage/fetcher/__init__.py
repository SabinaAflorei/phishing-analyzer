"""IMAP read-only + sursa statica de .eml. Nu sterge si nu muta mesaje."""

from __future__ import annotations

from pathlib import Path


def fetch_from_corpus(corpus_dir: Path) -> list[Path]:
    """Sursa offline pentru dezvoltare si teste."""
    raise NotImplementedError


def fetch_from_imap() -> list[Path]:
    """Poll read-only. Marcheaza procesatele in DB, nu le sterge. Idempotent la restart."""
    raise NotImplementedError
