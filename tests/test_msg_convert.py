"""Detectia formatului si conversia .msg -> .eml.

Detectia se face pe CONTINUT, nu pe extensie. Extensia o alege cel care trimite
fisierul, deci nu e o dovada - iar un mesaj salvat din Outlook ajunge des
redenumit pe drum.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from triage.msg_convert import (
    OLE_MAGIC,
    detect_format,
    looks_like_msg,
    looks_like_rfc822,
    msg_bytes_to_eml,
    to_eml,
)

EML = b"From: a@exemplu.ro\nTo: b@exemplu.ro\nSubject: test\n\nCorp.\n"
MSG_DIR = Path(__file__).parent.parent / "corpus" / "msg"


def _un_msg() -> bytes:
    files = sorted(MSG_DIR.glob("*.msg"))
    if not files:
        pytest.skip("corpus/msg/ lipseste")
    return files[0].read_bytes()


# ---------------------------------------------------------------------------
# Detectie
# ---------------------------------------------------------------------------


def test_semnatura_ole_inseamna_msg() -> None:
    assert looks_like_msg(OLE_MAGIC + b"orice") is True
    assert looks_like_msg(EML) is False


def test_headerul_inseamna_rfc822() -> None:
    assert looks_like_rfc822(EML) is True
    assert looks_like_rfc822(b"Received: from x\n\ncorp") is True


def test_liniile_goale_de_la_inceput_se_sar() -> None:
    assert looks_like_rfc822(b"\n\n\nFrom: a@b.ro\n\ncorp") is True


def test_prima_linie_de_mbox_e_acceptata() -> None:
    assert looks_like_rfc822(b"From cineva@exemplu.ro Mon Jan 1 00:00:00 2026\nSubject: x\n") is True


def test_ce_nu_e_email_nu_trece() -> None:
    assert looks_like_rfc822(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32) is False
    assert looks_like_rfc822(b"doar text simplu, fara headere\n") is False
    assert looks_like_rfc822(b"") is False


def test_mesajul_stricat_tot_trece() -> None:
    """Sectiunea 8.3: un mail malformat se analizeaza, nu se respinge din poarta."""
    assert looks_like_rfc822(b"From: \xff\xfe stricat\nSubject:\n\n") is True


def test_detect_format() -> None:
    assert detect_format(OLE_MAGIC + b"x") == "msg"
    assert detect_format(EML) == "eml"
    assert detect_format(b"\x00\x01\x02binar") == "unknown"


# ---------------------------------------------------------------------------
# Conversie
# ---------------------------------------------------------------------------


def test_to_eml_lasa_eml_ul_neatins() -> None:
    assert to_eml(EML) is EML


def test_conversia_produce_un_mesaj_analizabil() -> None:
    from triage.parser import parse_report

    eml = msg_bytes_to_eml(_un_msg())

    assert looks_like_rfc822(eml), "iesirea trebuie sa fie RFC822"
    assert not looks_like_msg(eml)
    parsed = parse_report(eml)
    assert parsed.from_address, "expeditorul trebuie sa se poata citi"


def test_conversia_e_determinista() -> None:
    """Boundary-uri dintr-un contor, nu random: acelasi .msg -> acelasi octet."""
    raw = _un_msg()
    assert msg_bytes_to_eml(raw) == msg_bytes_to_eml(raw)


def test_to_eml_converteste_msg_ul() -> None:
    raw = _un_msg()
    assert to_eml(raw) == msg_bytes_to_eml(raw)


def test_msg_stricat_ridica_eroare() -> None:
    """Semnatura corecta, continut aiurea: nu are voie sa treaca drept reusita."""
    with pytest.raises(Exception):
        msg_bytes_to_eml(OLE_MAGIC + b"nu e un .msg valid")
