from __future__ import annotations

from pathlib import Path

import pytest

from triage.cli import main
from triage.pipeline import ingest_bytes

PHISHING = (
    b"From: Atacator <rau@evil-domain.example>\n"
    b"To: coleg@exemplu.ro\n"
    b"Subject: Contul dumneavoastra\n"
    b"Authentication-Results: mx.exemplu.ro; spf=fail\n"
    b"\n"
    b"Confirmati contul aici: https://rau.example/login\n"
)


def test_check_fisier_inexistent(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", str(tmp_path / "lipsa.eml")]) == 1
    assert "nu exista" in capsys.readouterr().err


def test_check_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    eml = tmp_path / "sample.eml"
    eml.write_bytes(PHISHING)

    assert main(["check", str(eml), "--json"]) == 0
    out = capsys.readouterr().out
    assert '"verdict": "MALICIOUS"' in out
    assert '"AUTH_FAILURE"' in out


def test_check_nu_scrie_in_baza_de_date(tmp_path: Path) -> None:
    """`check` e pentru o privire rapida, nu pentru a baga mailul in coada."""
    from triage import db
    from triage.db import session

    eml = tmp_path / "sample.eml"
    eml.write_bytes(PHISHING)
    main(["check", str(eml)])

    with session() as s:
        assert db.list_reports(s) == []


def test_check_text(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    eml = tmp_path / "sample.eml"
    eml.write_bytes(PHISHING)

    assert main(["check", str(eml)]) == 0
    out = capsys.readouterr().out
    assert "MALICIOUS" in out
    assert "hxxps[://]rau[.]example/login" in out
    assert "https://" not in out, "niciun URL clicabil in output (criteriul 8.2)"


def test_check_mail_stricat_nu_arunca(tmp_path: Path) -> None:
    eml = tmp_path / "stricat.eml"
    eml.write_bytes(b"\xff\xfe complet aiurea")
    assert main(["check", str(eml)]) == 0


def test_ingest_si_list(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ingest_bytes(PHISHING)

    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "MALICIOUS" in out
    assert "Contul dumneavoastra" in out


def test_list_coada_goala(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list"]) == 0
    assert "Coada e goala" in capsys.readouterr().out


def test_list_filtrat(capsys: pytest.CaptureFixture[str]) -> None:
    ingest_bytes(PHISHING)
    assert main(["list", "--verdict", "SIMULATION"]) == 0
    assert "Coada e goala" in capsys.readouterr().out


def test_show(capsys: pytest.CaptureFixture[str]) -> None:
    report = ingest_bytes(PHISHING)
    assert report is not None

    assert main(["show", str(report.id)]) == 0
    out = capsys.readouterr().out
    assert "AUTH_FAILURE" in out
    assert "Ciorna de raspuns" in out


def test_show_json(capsys: pytest.CaptureFixture[str]) -> None:
    report = ingest_bytes(PHISHING)
    assert report is not None
    assert main(["show", str(report.id), "--json"]) == 0
    assert '"eml_sha256"' in capsys.readouterr().out


def test_show_inexistent(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["show", "999"]) == 1
    assert "Nu exista raportul" in capsys.readouterr().err


def test_ingest_din_corpus(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "a.eml").write_bytes(PHISHING)
    from triage.pipeline import ingest_corpus

    assert ingest_corpus(tmp_path).ingested == 1
    assert main(["list"]) == 0
    assert "MALICIOUS" in capsys.readouterr().out


def test_fara_subcomanda_da_eroare() -> None:
    with pytest.raises(SystemExit):
        main([])
