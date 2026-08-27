from __future__ import annotations

import re
from triage.drafter.prompts import STATIC_TEMPLATES
from triage.verdicts import Analysis, Verdict


def sanitize_for_model(text: str, max_chars: int = 2000) -> str:
    """Elimină tag-uri HTML, caractere speciale Unicode și trunchiază textul."""
    if not text:
        return ""

    # Elimină tag-urile HTML
    clean_text = re.sub(r"<[^>]*>", " ", text)
    # Elimină caracterele direcționale Unicode și control zero-width
    clean_text = re.sub(r"[\u200B-\u200D\u200E\u200F\u202A-\u202E]", "", clean_text)
    # Normalizează spațiile albe
    clean_text = re.sub(r"\s+", " ", clean_text).strip()

    return clean_text[:max_chars]


def build_draft(analysis: Analysis, reporter_name: str) -> str:
    """Generează draftul de răspuns.
    
    Dacă verdictul este NEEDS_REVIEW, returnează un string gol.
    Altfel, aplică șablonul static potrivit pe baza numelui raportorului.
    """
    if analysis.verdict is Verdict.NEEDS_REVIEW:
        return ""

    # Extrage prenumele (primul cuvânt din nume)
    prenume = reporter_name.strip().split()[0] if reporter_name.strip() else "Coleg"

    verdict_key = analysis.verdict.name  # ex: "SIMULATION", "MALICIOUS", "LEGITIMATE"
    
    template = STATIC_TEMPLATES.get(verdict_key)
    if not template:
        return ""

    return template.format(prenume=prenume)