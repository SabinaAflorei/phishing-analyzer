"""Incarcarea configurarii, mai ales calea de rezerva.

`config.py` decide daca regulile ruleaza pe datele reale ale companiei sau pe
cele din `.example`. Era modulul cu cea mai slaba acoperire din tot arborele
(74%), si tocmai ramura de rezerva nu era atinsa de niciun test - adica exact
comportamentul din care se poate ajunge, tacut, la jumatate din reguli rulate
pe date de exemplu.

Avertismentul nu e cosmetic: fara el descoperi peste doua saptamani ca
`company_domains.yaml` nu a fost niciodata copiat pe masina.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from triage import config


@pytest.fixture
def config_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Un director de configurare gol, izolat de cel real al masinii."""
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    return tmp_path


def test_fisierul_real_are_prioritate_fata_de_example(config_dir: Path) -> None:
    (config_dir / "test.yaml").write_text("cheie: real\n", encoding="utf-8")
    (config_dir / "test.example.yaml").write_text("cheie: exemplu\n", encoding="utf-8")

    assert config.load_yaml_config("test.yaml") == {"cheie": "real"}


def test_fara_fisier_real_se_cade_pe_example_cu_avertisment(
    config_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """CI si orice clona noua nu au fisierele reale - sunt in .gitignore.

    Fara rezerva, `.get(cheie, [])` ar intoarce liste goale si regulile ar deveni
    cod mort care nu se plange niciodata. Rezerva exista tocmai ca sa nu fie asa,
    dar trebuie sa se AUDA.
    """
    (config_dir / "test.example.yaml").write_text("cheie: exemplu\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="triage.config"):
        data = config.load_yaml_config("test.yaml")

    assert data == {"cheie": "exemplu"}
    assert "test.example.yaml" in caplog.text
    assert "test.yaml" in caplog.text


def test_fara_niciun_fisier_intoarce_dictionar_gol_si_striga(
    config_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger="triage.config"):
        data = config.load_yaml_config("lipseste.yaml")

    assert data == {}
    assert caplog.records, "lipsa completa a configurarii trebuie sa fie o eroare in log"


def test_resolve_config_path_intoarce_none_cand_nu_exista_nimic(config_dir: Path) -> None:
    assert config.resolve_config_path("lipseste.yaml") is None


@pytest.mark.parametrize("continut", ["", "- doar\n- o\n- lista\n", "doar un sir\n"])
def test_yaml_care_nu_e_dictionar_devine_dictionar_gol(config_dir: Path, continut: str) -> None:
    """Un YAML gol sau o lista la radacina nu au voie sa doboare pornirea.

    Apelantii fac `.get(...)` pe rezultat; daca ar primi None sau o lista, ar
    cadea cu AttributeError la import, adica inainte sa poata loga ceva util.
    """
    (config_dir / "ciudat.yaml").write_text(continut, encoding="utf-8")

    assert config.load_yaml_config("ciudat.yaml") == {}


def test_require_keys_tace_cand_totul_e_prezent(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR, logger="triage.config"):
        config.require_keys({"a": 1, "b": 2}, ["a", "b"], "test.yaml")

    assert not caplog.records


def test_require_keys_numeste_cheile_lipsa(caplog: pytest.LogCaptureFixture) -> None:
    """`.get(cheie_scrisa_gresit, [])` nu da eroare, doar tacere - si tacerea a
    costat deja doua regresii. Mesajul trebuie sa spuna CARE cheie lipseste."""
    with caplog.at_level(logging.ERROR, logger="triage.config"):
        config.require_keys({"a": 1}, ["a", "b", "c"], "attachment_rules.yaml")

    assert "attachment_rules.yaml" in caplog.text
    assert "b" in caplog.text and "c" in caplog.text


def test_config_dir_gasit_contine_fisierele_reale() -> None:
    """Cautarea in sus prin ierarhie chiar gaseste `config/` al proiectului."""
    assert config.CONFIG_DIR.is_dir()
    assert (config.CONFIG_DIR / "attachment_rules.yaml").is_file()
