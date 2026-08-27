from __future__ import annotations

from triage.drafter import build_draft, sanitize_for_model
from triage.verdicts import Analysis, Verdict


def test_sanitize_for_model():
    raw_text = "<html><body>Salut<script>alert(1)</script></body></html>"
    clean = sanitize_for_model(raw_text)
    assert "<" not in clean
    assert "Salut" in clean


def test_build_draft_needs_review():
    analysis = Analysis(verdict=Verdict.NEEDS_REVIEW, confidence=0.5)
    assert build_draft(analysis, "Ion Popescu") == ""


def test_build_draft_simulation():
    analysis = Analysis(verdict=Verdict.SIMULATION, confidence=1.0)
    draft = build_draft(analysis, "Maria Ionescu")
    assert "Bună ziua, Maria," in draft
    assert "Cu stimă," in draft


def test_build_draft_malicious():
    analysis = Analysis(verdict=Verdict.MALICIOUS, confidence=0.9)
    draft = build_draft(analysis, "Andrei")
    assert "Bună ziua, Andrei," in draft
    assert "periculos" in draft