"""Criteriu de acceptanta: verdictul nu se schimba din cauza textului din mail."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.mark.xfail(
    reason="de implementat: analyzer + corpus/eml/08_prompt_injection.eml",
    strict=False,
)
def test_hidden_injection_does_not_change_verdict(corpus_dir: Path) -> None:
    """Mail-ul contine, in text alb pe alb, instructiuni catre model.
    Verdictul produs de analizorul determinist trebuie sa fie identic cu si
    fara textul ascuns."""
    raise NotImplementedError
