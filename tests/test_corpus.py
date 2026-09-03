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

import email
from email import policy
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from triage.verdicts import Verdict

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


# TODO(lipseste testul cel mai important): niciun test nu compara verdictul REAL
# cu expected_verdict din yaml.
# Ce e gresit: fisierul asta verifica doar ca datele sunt intregi si ca yaml-urile
# sunt valide - ceea ce e util, dar nu cheama niciodata analyze(). Ai 12 cazuri cu
# verdict asteptat scris in corpus/expected/ si nefolosit de nimeni.
# De ce conteaza: practic TOATE bug-urile marcate cu TODO in analyzer si parser ar
# fi fost prinse de testul asta, in loc sa fie descoperite la review.
# Cum rezolvi: un test parametrizat pe cazuri - citesti .eml, parse_report(),
# analyze(), si compari result.verdict cu data["expected_verdict"]. Pune pe el
# acelasi decorator @_no_corpus care exista deja mai jos, ca sa se sara pe masinile
# fara corpus in loc sa pice. Verifica si must_contain_evidence cand incepi sa
# completezi listele alea.
@_no_corpus
@pytest.mark.parametrize("case", _cases())
def test_eml_e_privat(case: str) -> None:
    """Continut sensibil: 600, ca in sectiunea 4.5."""
    mode = (EML_DIR / f"{case}.eml").stat().st_mode & 0o777
    assert mode == 0o600, f"{case}.eml are permisiuni {mode:o}, se astepta 600"
