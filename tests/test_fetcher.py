from __future__ import annotations

from pathlib import Path
from triage.fetcher import fetch_from_corpus, fetch_from_imap


def test_fetch_from_corpus_non_existent(tmp_path: Path):
    invalid_dir = tmp_path / "does_not_exist"
    assert fetch_from_corpus(invalid_dir) == []

def test_fetch_from_corpus_success(tmp_path: Path):
   
    file1 = tmp_path / "1.msg"
    file2 = tmp_path / "2.eml"
    file1.touch()
    file2.touch()

    (tmp_path / "ignore.txt").touch()

    results = fetch_from_corpus(tmp_path)
    assert len(results) == 2
    assert file1 in results
    assert file2 in results

def test_fetch_from_imap():
    assert fetch_from_imap() == []