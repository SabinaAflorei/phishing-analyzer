"""Corpusul si asteptarile lui trebuie sa ramana sincronizate.

Nu testeaza analizorul - testeaza ca datele pe care se sprijina toate celelalte
teste sunt intregi: fiecare .eml are un expected/<caz>.yaml, fiecare yaml are
un .eml, verdictele sunt din vocabularul definit, iar fisierele chiar se parseaza
ca RFC822. Cand cineva redenumeste un caz si uita jumatate, afli aici, nu peste
doua ore intr-un test de analizor care pare ca a inceput sa halucineze.

Corpusul contine mail-uri reale si nu intra in git (vezi README, sectiunea
"Date sensibile si git").
Pe o masina fara el, testele se sar cu un mesaj clar in loc sa pice.
"""

from __future__ import annotations

import sys

import email
from email import policy
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from triage.analyzer import SIGNAL_WEIGHT, analyze
from triage.drafter import generate_draft
from triage.parser import parse_report
from triage.pipeline import ingest_corpus
from triage.verdicts import Analysis, Verdict

CORPUS = Path(__file__).parent.parent / "corpus"
EML_DIR = CORPUS / "eml"
EXPECTED_DIR = CORPUS / "expected"

_no_corpus = pytest.mark.skipif(
    not list(EML_DIR.glob("*.eml")),
    reason="corpus/eml/ e gol - vezi README, sectiunea Corpusul de test",
)


def _cases() -> list[str]:
    return sorted(p.stem for p in EXPECTED_DIR.glob("*.yaml"))


def test_exista_asteptari() -> None:
    assert _cases(), "corpus/expected/ nu contine niciun yaml"


@pytest.mark.parametrize("case", _cases())
def test_yaml_e_valid(case: str) -> None:
    data = yaml.safe_load((EXPECTED_DIR / f"{case}.yaml").read_text(encoding="utf-8"))
    assert data["case"] == case, "campul 'case' trebuie sa fie identic cu numele fisierului"
    assert data["expected_verdict"] in set(Verdict), (
        f"{case}: verdict necunoscut {data['expected_verdict']!r}"
    )
    assert isinstance(data["must_contain_evidence"], list)


@_no_corpus
@pytest.mark.parametrize("case", _cases())
def test_fiecare_caz_are_eml(case: str) -> None:
    assert (EML_DIR / f"{case}.eml").is_file(), f"lipseste corpus/eml/{case}.eml"


@_no_corpus
def test_niciun_eml_orfan() -> None:
    orfane = {p.stem for p in EML_DIR.glob("*.eml")} - set(_cases())
    assert not orfane, f".eml fara expected/*.yaml: {sorted(orfane)}"


@_no_corpus
@pytest.mark.parametrize("case", _cases())
def test_eml_se_parseaza(case: str) -> None:
    """Chiar si cazul 09, cel malformat intentionat, trebuie sa se parseze
    fara exceptie. Parser-ul de mai tarziu are voie sa gaseasca headere lipsa,
    nu are voie sa arunce."""
    path = EML_DIR / f"{case}.eml"
    with path.open("rb") as fh:
        msg = email.message_from_binary_file(fh, policy=cast(Any, policy.default))
    assert msg is not None
    list(msg.walk())  # structura MIME e traversabila cap-coada


@_no_corpus
@pytest.mark.skipif(sys.platform == "win32", reason="permisiuni POSIX")
@pytest.mark.parametrize("case", _cases())
def test_eml_e_privat(case: str) -> None:
    """Continut sensibil: 600, ca in sectiunea 4.5."""
    mode = (EML_DIR / f"{case}.eml").stat().st_mode & 0o777
    assert mode == 0o600, f"{case}.eml are permisiuni {mode:o}, se astepta 600"


# ---------------------------------------------------------------------------
# Testul care conteaza: verdictul REAL fata de cel asteptat (criteriul 8.1)
# ---------------------------------------------------------------------------


def _expected(case: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        yaml.safe_load((EXPECTED_DIR / f"{case}.yaml").read_text(encoding="utf-8")),
    )


def _analyze(case: str) -> Analysis:
    return analyze(parse_report((EML_DIR / f"{case}.eml").read_bytes()))


@_no_corpus
@pytest.mark.parametrize("case", _cases())
def test_verdictul_e_cel_asteptat(case: str) -> None:
    """Criteriul 8.1: fiecare caz din corpus primeste verdictul corect.

    Practic toate bug-urile marcate cu TODO in analizor si parser ar fi fost
    prinse aici, in loc sa fie descoperite la review.
    """
    expected = _expected(case)
    result = _analyze(case)
    assert result.verdict == expected["expected_verdict"], (
        f"{case}: asteptat {expected['expected_verdict']}, obtinut {result.verdict} "
        f"[{', '.join(ev.code for ev in result.evidence)}]"
    )


@_no_corpus
@pytest.mark.parametrize("case", _cases())
def test_dovezile_obligatorii_sunt_prezente(case: str) -> None:
    """Verdictul singur nu ajunge. Doua cazuri pot iesi MALICIOUS din motive
    complet diferite; cand unul se strica vrei sa afli CARE semnal a disparut."""
    required = set(_expected(case)["must_contain_evidence"])
    produced = {ev.code for ev in _analyze(case).evidence}
    assert required <= produced, f"{case}: lipsesc dovezile {sorted(required - produced)}"


@_no_corpus
@pytest.mark.parametrize("case", _cases())
def test_dovezile_folosesc_vocabularul_definit(case: str) -> None:
    """Un cod fara pondere ar conta zero in tacere, adica ar fi cod mort."""
    produced = {ev.code for ev in _analyze(case).evidence}
    assert produced <= set(SIGNAL_WEIGHT), (
        f"{case}: coduri necunoscute {produced - set(SIGNAL_WEIGHT)}"
    )


@_no_corpus
@pytest.mark.parametrize("case", _cases())
def test_niciun_url_clicabil_in_output(case: str) -> None:
    """Criteriul 8.2, pe iesirea analizorului: dovezile ajung in baza de date,
    in dashboard si in log-uri, deci trebuie sa fie deja defangate."""
    for ev in _analyze(case).evidence:
        assert "http://" not in ev.detail, f"{case}: URL clicabil in {ev.code}"
        assert "https://" not in ev.detail, f"{case}: URL clicabil in {ev.code}"


@_no_corpus
@pytest.mark.parametrize("case", _cases())
def test_pipeline_ul_produce_draft_pentru_verdictele_actionabile(case: str) -> None:
    """NEEDS_REVIEW nu primeste draft automat - nici sistemul nu stie ce e mailul.
    Restul verdictelor primesc, mereu, cel putin template-ul static."""
    parsed = parse_report((EML_DIR / f"{case}.eml").read_bytes())
    analysis = analyze(parsed)
    draft = generate_draft(analysis, parsed.reporter_display_name or "Coleg")

    if analysis.verdict == Verdict.NEEDS_REVIEW:
        assert draft.text == ""
    else:
        assert "Cu stimă," in draft.text, f"{case}: draft fara incheiere"


@_no_corpus
def test_ingestia_intregului_corpus_e_idempotenta() -> None:
    """Criteriul I9, pe date reale: a doua rulare nu adauga nimic."""
    first = ingest_corpus(EML_DIR)
    assert first.ingested == len(_cases())
    assert first.failed == 0, first.errors

    second = ingest_corpus(EML_DIR)
    assert (second.ingested, second.failed) == (0, 0)
    assert second.skipped == len(_cases())
