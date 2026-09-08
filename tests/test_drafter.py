from __future__ import annotations

from triage.drafter import build_draft, sanitize_for_model
from triage.drafter.prompts import STATIC_TEMPLATES, split_email
from triage.verdicts import Analysis, Verdict, Evidence, Severity


def test_sanitize_for_model_basic() -> None:
    raw_text = "<html><body>Salut<script>alert(1)</script><style>body {color: red;}</style></body></html>"
    clean = sanitize_for_model(raw_text)

    # Verificare ca nu exista tag-uri HTML si nici continutul din <script> / <style>
    assert "<" not in clean
    assert "Salut" in clean
    assert "alert" not in clean
    assert "color: red" not in clean


def test_sanitize_for_model_zero_width_chars() -> None:
    # Text ce contine caractere invizibile zero-width si Unicode direcționale (\uFEFF, \u200B, \u2060, \u2066)
    raw_text = "Sa\uFEFFlut\u200B lume\u2060!\u2066"
    clean = sanitize_for_model(raw_text)
    assert clean == "Salut lume!"


def test_sanitize_for_model_empty_and_none() -> None:
    assert sanitize_for_model("") == ""


def test_sanitize_for_model_truncation() -> None:
    text = "Acesta este un text lung care trebuie trunchiat curat fără a tăia cuvinte."
    # Trunchiere la 25 de caractere -> "Acesta este un text lung"
    clean = sanitize_for_model(text, max_chars=25)
    assert len(clean) <= 25
    assert clean == "Acesta este un text lung"


def test_build_draft_needs_review() -> None:
    analysis = Analysis(verdict=Verdict.NEEDS_REVIEW, confidence=0.5)
    assert build_draft(analysis, "Ion Popescu") == ""


def test_build_draft_simulation() -> None:
    analysis = Analysis(verdict=Verdict.SIMULATION, confidence=1.0)
    draft = build_draft(analysis, "Maria Ionescu")
    assert "Bună ziua, Maria," in draft
    assert "Cu stimă," in draft


def test_build_draft_malicious() -> None:
    analysis = Analysis(verdict=Verdict.MALICIOUS, confidence=0.9)
    draft = build_draft(analysis, "Andrei")
    assert "Bună ziua, Andrei," in draft
    assert "periculos" in draft


def test_build_draft_spam() -> None:
    analysis = Analysis(verdict=Verdict.SPAM, confidence=0.8)
    draft = build_draft(analysis, "Elena")
    assert "Bună ziua, Elena," in draft
    assert "publicitate nesolicitată" in draft
    assert "Cu stimă," in draft


def test_build_draft_legitimate() -> None:
    analysis = Analysis(verdict=Verdict.LEGITIMATE, confidence=0.95)
    draft = build_draft(analysis, "Popescu, Ion")
    assert "Bună ziua, Ion," in draft
    assert "legitim" in draft
    assert "Cu stimă," in draft


def test_build_draft_empty_reporter_name() -> None:
    analysis = Analysis(verdict=Verdict.MALICIOUS, confidence=0.9)
    draft = build_draft(analysis, "")
    assert draft.startswith("Bună ziua,\n\n")  


def test_static_templates_valid_email_structure() -> None:
    """Verifică ca fiecare șablon static să aibă structura validă din 3 părți (salut, corp, încheiere)."""
    for verdict_key, template in STATIC_TEMPLATES.items():
        formatted_email = template.format(prenume="Test")
        greeting, body, closing = split_email(formatted_email)

        assert greeting != "", f"Șablonul static pentru {verdict_key} nu are un salut valid."
        assert body != "", f"Șablonul static pentru {verdict_key} nu are corp de mesaj."
        assert closing != "", f"Șablonul static pentru {verdict_key} nu are o încheiere validă."

def test_build_draft_with_working_llm_client_uses_evidence() -> None:
    """Regresie: evidence_text nedefinit cauza NameError la orice draft
    generat prin LLM real, mascat de except Exception generic care cadea
    silentios pe fallback static."""

    class _FakeWorkingClient:
        def generate(self, system_prompt: str, prompt: str, temperature: float = 0.1) -> str:
            assert "Dovezi analiză" in prompt
            return "Bună ziua, Ion,\n\nText de test.\n\nCu stimă,"

    analysis = Analysis(
        verdict=Verdict.MALICIOUS,
        confidence=0.9,
        evidence=[Evidence(code="AUTH_FAILURE", severity=Severity.HIGH, description="test")],
    )
    draft = build_draft(analysis=analysis, reporter_name="Ion", llm_client=_FakeWorkingClient())
    assert "Text de test" in draft        