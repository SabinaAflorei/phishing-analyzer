from __future__ import annotations

from pathlib import Path

import imaplib
from typing import Any

import pytest

from triage.fetcher import (
    ImapMessage,
    MailboxUnavailable,
    fetch_from_corpus,
    fetch_from_imap,
    save_raw_eml,
)
from triage.settings import ImapSettings


def test_fetch_from_corpus_non_existent(tmp_path: Path) -> None:
    invalid_dir = tmp_path / "does_not_exist"
    assert fetch_from_corpus(invalid_dir) == []


def test_fetch_from_corpus_success(tmp_path: Path) -> None:
    file1 = tmp_path / "1.eml"
    file2 = tmp_path / "2.eml"
    file1.touch()
    file2.touch()

    (tmp_path / "ignore.txt").touch()

    results = fetch_from_corpus(tmp_path)
    assert len(results) == 2
    assert results == [file1, file2]
    assert all(p.suffix.lower() == ".eml" for p in results)


def test_fetch_from_corpus_case_insensitive(tmp_path: Path) -> None:
    """Verifică dacă sunt detectate și fișierele .EML sau .Eml (case-insensitive)."""
    file_upper = tmp_path / "mail1.EML"
    file_mixed = tmp_path / "mail2.Eml"
    file_upper.touch()
    file_mixed.touch()

    results = fetch_from_corpus(tmp_path)
    assert len(results) == 2
    assert results == [file_upper, file_mixed]


def test_fetch_from_corpus_ignores_non_eml(tmp_path: Path) -> None:
    """Verifică ignorarea fișierelor care nu sunt e-mailuri RFC822 (.msg, .txt, etc.)."""
    (tmp_path / "test.eml").touch()
    (tmp_path / "legacy.msg").touch()
    (tmp_path / "document.pdf").touch()
    (tmp_path / "notes.txt").touch()

    results = fetch_from_corpus(tmp_path)
    assert len(results) == 1
    assert results[0].name == "test.eml"


# ---------------------------------------------------------------------------
# IMAP - fara retea. Conexiunea se injecteaza, deci testele ruleaza cu
# socket-urile blocate, ca tot restul suitei.
# ---------------------------------------------------------------------------

CONFIGURAT = ImapSettings(
    host="imap.exemplu.ro", port=993, user="itsec@exemplu.ro", app_password="secret"
)

MESAJ = b"From: coleg@exemplu.ro\nSubject: Raportare\n\nVezi mailul asta."


class FakeIMAP:
    """Cat imaplib foloseste fetcher-ul, si nimic mai mult."""

    def __init__(self, uids: list[bytes] | None = None, *, select_ok: bool = True) -> None:
        self.uids = [b"1", b"2"] if uids is None else uids
        self.select_ok = select_ok
        self.closed = False
        self.readonly: bool | None = None
        self.written: list[Any] = []

    def select(self, folder: str, readonly: bool = False) -> tuple[str, Any]:
        self.readonly = readonly
        return ("OK" if self.select_ok else "NO", [b""])

    def search(self, charset: Any, criteria: str) -> tuple[str, list[bytes]]:
        return ("OK", [b" ".join(self.uids)])

    def fetch(self, uid: bytes, parts: str) -> tuple[str, list[Any]]:
        return ("OK", [(b"1 (RFC822 {50}", MESAJ + b" uid=" + uid), b")"])

    def store(self, *args: Any) -> None:
        self.written.append(args)

    def close(self) -> None:
        self.closed = True

    def logout(self) -> None:
        pass


def test_imap_neconfigurat_nu_face_nimic() -> None:
    """Pana la discutia cu mentorul (sectiunea 10), .env e gol si nu se conecteaza."""
    assert fetch_from_imap(ImapSettings()) == []


def test_imap_citeste_mesajele() -> None:
    fake = FakeIMAP()
    messages = fetch_from_imap(CONFIGURAT, connect=lambda _: fake)
    assert [m.uid for m in messages] == ["1", "2"]
    assert messages[0].raw.startswith(b"From: coleg@exemplu.ro")


def test_imap_deschide_folderul_read_only() -> None:
    """Criteriul din 6.1: nu sterge si nu marcheaza. readonly=True e garantia."""
    fake = FakeIMAP()
    fetch_from_imap(CONFIGURAT, connect=lambda _: fake)
    assert fake.readonly is True
    assert fake.written == [], "fetcher-ul nu are voie sa scrie flag-uri pe mailbox"


def test_imap_inchide_conexiunea() -> None:
    fake = FakeIMAP()
    fetch_from_imap(CONFIGURAT, connect=lambda _: fake)
    assert fake.closed is True


def test_imap_reincearca_si_apoi_renunta_curat() -> None:
    """Criteriul 8.3: mailbox indisponibil duce la retry, fara pierdere de mesaje.
    Nimic nu s-a modificat pe server, deci urmatorul poll ia totul de la capat."""
    incercari: list[int] = []
    pauze: list[float] = []

    def connect_care_pica(_: ImapSettings) -> Any:
        incercari.append(1)
        raise OSError("connection refused")

    with pytest.raises(MailboxUnavailable):
        fetch_from_imap(
            CONFIGURAT,
            connect=connect_care_pica,
            retries=3,
            backoff_seconds=0.5,
            sleep=pauze.append,
        )

    assert len(incercari) == 3
    assert pauze == [0.5, 1.0], "asteptarea trebuie sa creasca intre incercari"


def test_imap_reuseste_dupa_o_cadere() -> None:
    stare = {"apeluri": 0}

    def connect_intermitent(_: ImapSettings) -> Any:
        stare["apeluri"] += 1
        if stare["apeluri"] == 1:
            raise imaplib.IMAP4.error("server busy")
        return FakeIMAP(uids=[b"7"])

    messages = fetch_from_imap(CONFIGURAT, connect=connect_intermitent, sleep=lambda _: None)
    assert [m.uid for m in messages] == ["7"]


def test_imap_sare_peste_un_mesaj_ilizibil_fara_sa_pice() -> None:
    class FetchStricat(FakeIMAP):
        def fetch(self, uid: bytes, parts: str) -> tuple[str, list[Any]]:
            if uid == b"1":
                return ("NO", [])
            return super().fetch(uid, parts)

    messages = fetch_from_imap(CONFIGURAT, connect=lambda _: FetchStricat())
    assert [m.uid for m in messages] == ["2"]


def test_imap_semnaleaza_folder_inexistent() -> None:
    with pytest.raises(MailboxUnavailable):
        fetch_from_imap(
            CONFIGURAT, connect=lambda _: FakeIMAP(select_ok=False), sleep=lambda _: None
        )


def test_hash_ul_mesajului_e_stabil() -> None:
    """Cheia de idempotenta. Acelasi mesaj, acelasi hash, la orice repornire."""
    assert ImapMessage("1", MESAJ).sha256 == ImapMessage("99", MESAJ).sha256


def test_save_raw_eml_scrie_cu_permisiuni_restrictive(tmp_path: Path) -> None:
    destination = save_raw_eml(MESAJ, tmp_path / "brute" / "a.eml")
    assert destination.read_bytes() == MESAJ
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.parent.stat().st_mode & 0o777 == 0o700
