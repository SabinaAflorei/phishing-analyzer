from __future__ import annotations

from triage.drafter import build_draft, sanitize_for_model
from triage.verdicts import Analysis, Verdict


# TODO: lipsesc testele pentru trunchierea la max_chars, pentru caracterele
# zero-width si pentru text gol.
# TODO: testele din fisier nu au adnotarea de retur -> None, spre deosebire de
# restul suitei (vezi tests/test_analyzer.py si tests/test_corpus.py).
def test_sanitize_for_model():
    raw_text = "<html><body>Salut<script>alert(1)</script></body></html>"
    clean = sanitize_for_model(raw_text)
    # TODO: verifica doar ca nu a ramas "<". Trece si cand textul din <script>
    # ramane intreg, adica exact cazul care conteaza. Verifica si continutul.
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


# TODO: lipsesc testele pentru SPAM si LEGITIMATE si pentru numele gol ("Coleg").
# TODO: lipseste testul care trece fiecare sablon static prin split_email si
# verifica ca are toate cele trei parti - salut, corp, incheiere.
