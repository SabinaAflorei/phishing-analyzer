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


# ---------------------------------------------------------------------------
# show --draft: ciorna curata, ca sa poata fi trecuta prin pipe
# ---------------------------------------------------------------------------


def test_show_draft_scoate_doar_ciorna(capsys: pytest.CaptureFixture[str]) -> None:
    """`triage show 3 --draft | clip` trebuie sa puna in clipboard NUMAI mesajul.

    Fara chenare, fara dovezi, fara antet: analistul lipeste rezultatul direct in
    clientul lui de mail. Un singur rand in plus si trebuie sa curete de mana.
    """
    report = ingest_bytes(PHISHING)
    assert report is not None

    assert main(["show", str(report.id), "--draft"]) == 0
    out = capsys.readouterr().out

    assert out.startswith("Bună ziua")
    assert out.rstrip().endswith("Cu stimă,")
    assert "AUTH_FAILURE" not in out
    assert "=" * 68 not in out


def test_show_draft_pe_needs_review_e_gol(capsys: pytest.CaptureFixture[str]) -> None:
    """NEEDS_REVIEW nu produce ciorna, deci nici `--draft` nu are ce scoate."""
    report = ingest_bytes(b"From: cineva@necunoscut.example\nSubject: ?\n\nnimic concludent\n")
    assert report is not None
    assert report.verdict == "NEEDS_REVIEW"

    assert main(["show", str(report.id), "--draft"]) == 0
    assert capsys.readouterr().out.strip() == ""


# ---------------------------------------------------------------------------
# stats: metricile din 8.4 din linia de comanda
# ---------------------------------------------------------------------------


def test_stats_pe_baza_goala(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["stats"]) == 0
    assert "goala" in capsys.readouterr().out


def test_stats_arata_matricea_de_corectii(capsys: pytest.CaptureFixture[str]) -> None:
    """Matricea (automat -> corectat) e informatia pentru care exista comanda.

    Ea spune care verdict e cel mai des schimbat de analist si in ce, adica pe ce
    se calibreaza ponderile din SIGNAL_WEIGHT.
    """
    from triage import db
    from triage.db import session

    report = ingest_bytes(PHISHING)
    assert report is not None
    with session() as s:
        db.set_verdict_override(s, report.id, "SPAM")

    assert main(["stats"]) == 0
    out = capsys.readouterr().out

    assert "MALICIOUS" in out and "SPAM" in out
    assert "->" in out


def test_stats_json(capsys: pytest.CaptureFixture[str]) -> None:
    ingest_bytes(PHISHING)
    assert main(["stats", "--json"]) == 0
    out = capsys.readouterr().out

    assert '"correction_matrix"' in out
    assert '"verdict_distribution"' in out


# ---------------------------------------------------------------------------
# check accepta si .msg
# ---------------------------------------------------------------------------

MSG_DIR = Path(__file__).parent.parent / "corpus" / "msg"


def test_check_converteste_msg_ul(capsys: pytest.CaptureFixture[str]) -> None:
    """Dashboard-ul stia sa converteasca .msg, CLI-ul nu. Aceeasi conducta acum."""
    files = sorted(MSG_DIR.glob("*.msg"))
    if not files:
        pytest.skip("corpus/msg/ lipseste")

    assert main(["check", str(files[0])]) == 0
    out = capsys.readouterr().out
    assert "Verdict:" in out


def test_check_ramane_permisiv_cu_ce_nu_e_msg(tmp_path: Path) -> None:
    """Conversia .msg nu are voie sa introduca o poarta de respingere.

    Dropzone-ul din dashboard respinge ce nu e e-mail, si acolo are sens: cineva
    poate trage din greseala o poza in pagina. Aici operatorul a numit fisierul
    explicit, iar criteriul 8.3 cere ca un mail malformat sa fie ANALIZAT, nu
    refuzat - altfel exact cazul 09 din corpus ar iesi din acoperire.
    """
    poza = tmp_path / "poza.eml"
    poza.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)

    assert main(["check", str(poza)]) == 0
