from __future__ import annotations

from pathlib import Path
from triage.fetcher import fetch_from_corpus, fetch_from_imap


# TODO: testele din fisier nu au adnotarea de retur -> None, spre deosebire de
# restul suitei (vezi tests/test_analyzer.py si tests/test_corpus.py).
def test_fetch_from_corpus_non_existent(tmp_path: Path):
    invalid_dir = tmp_path / "does_not_exist"
    assert fetch_from_corpus(invalid_dir) == []

def test_fetch_from_corpus_success(tmp_path: Path):
   
    # TODO: testul cere ca .msg sa fie returnat, dar pipeline-ul lucreaza doar cu
    # .eml. Asa se blocheaza bugul din fetcher in loc sa fie prins.
    file1 = tmp_path / "1.msg"
    file2 = tmp_path / "2.eml"
    file1.touch()
    file2.touch()

    (tmp_path / "ignore.txt").touch()

    results = fetch_from_corpus(tmp_path)
    assert len(results) == 2
    assert file1 in results
    assert file2 in results

# TODO: testeaza stub-ul, adica nimic. Se sterge cand fetcher-ul chiar face IMAP.
def test_fetch_from_imap():
    assert fetch_from_imap() == []


# TODO: lipsesc testele pentru .EML cu majuscule si pentru fisier care nu e mail.
