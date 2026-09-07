from __future__ import annotations

from triage.drafter import build_draft
from triage.drafter.llm_client import OllamaError
from triage.drafter.prompts import STATIC_TEMPLATES
from triage.verdicts import Analysis, Evidence, Severity, Verdict


class _BrokenLLMClient:
    """Simuleaza Ollama picat sau indisponibil - orice apel ridica OllamaError."""

    def generate(self, system_prompt: str, prompt: str, temperature: float = 0.1) -> str:
        raise OllamaError("Connection refused - simulare Ollama indisponibil")


class _InvalidOutputLLMClient:
    """Simuleaza un raspuns de model care nu respecta formatul asteptat."""

    def generate(self, system_prompt: str, prompt: str, temperature: float = 0.1) -> str:
        return "raspuns fara structura salut/corp/incheiere"


def _malicious_analysis() -> Analysis:
    return Analysis(
        verdict=Verdict.MALICIOUS,
        confidence=0.9,
        evidence=[Evidence(code="AUTH_FAILURE", severity=Severity.HIGH, description="test")],
    )


def test_ollama_down_falls_back_to_static_template() -> None:
    """Criteriu 8.3: Ollama indisponibil -> sistemul continua, foloseste template static."""
    analysis = _malicious_analysis()
    draft = build_draft(analysis=analysis, reporter_name="Ion", llm_client=_BrokenLLMClient())

    expected_static = STATIC_TEMPLATES["MALICIOUS"].format(prenume=", Ion")
    assert draft == expected_static


def test_invalid_llm_output_falls_back_to_static_template() -> None:
    """Criteriu 4.4 punctul 3: output invalid de la model -> se aruncă, se folosește template static."""
    analysis = _malicious_analysis()
    draft = build_draft(analysis=analysis, reporter_name="Ion", llm_client=_InvalidOutputLLMClient())

    expected_static = STATIC_TEMPLATES["MALICIOUS"].format(prenume=", Ion")
    assert draft == expected_static


def test_no_llm_client_uses_static_template_directly() -> None:
    """llm_client=None (offline-first, enrichment/llm dezactivat) -> template static direct."""
    analysis = _malicious_analysis()
    draft = build_draft(analysis=analysis, reporter_name="Ion", llm_client=None)

    expected_static = STATIC_TEMPLATES["MALICIOUS"].format(prenume=", Ion")
    assert draft == expected_static