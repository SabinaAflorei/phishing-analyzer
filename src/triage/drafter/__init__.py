"""LLM local. Primeste verdictul + dovezile. NU are voie sa schimbe verdictul."""

from __future__ import annotations

from triage.verdicts import Analysis, Verdict


def sanitize_for_model(text: str, max_chars: int = 2000) -> str:
    """Elimina tag-uri HTML, text ascuns (culoare = fundal), caractere zero-width
    si directionale Unicode. Apoi trunchiaza agresiv."""
    raise NotImplementedError


def build_draft(analysis: Analysis, reporter_name: str) -> str:
    """Fallback obligatoriu pe template static daca Ollama nu raspunde sau
    output-ul e invalid. Sistemul nu se blocheaza niciodata din cauza modelului."""
    if analysis.verdict is Verdict.NEEDS_REVIEW:
        return ""  # fara draft, se escaleaza
    raise NotImplementedError
