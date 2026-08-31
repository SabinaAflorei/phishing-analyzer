from __future__ import annotations

from pathlib import Path

from triage.fetcher import fetch_from_corpus, fetch_from_imap


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


def test_fetch_from_imap() -> None:
    assert fetch_from_imap() == []