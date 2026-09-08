from pathlib import Path

from triage.db import get_session, init_db, list_reports
from triage.ingest import ingest_corpus
import json
from conftest import requires_corpus


def test_ingest_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "test.sqlite3"
    init_db(db_path)

    corpus_dir = Path(__file__).resolve().parents[1] / "corpus" / "eml"

    first_count = ingest_corpus(corpus_dir)
    session = get_session()
    rows_after_first = len(list_reports(session))
    session.close()

    second_count = ingest_corpus(corpus_dir)
    session = get_session()
    rows_after_second = len(list_reports(session))
    session.close()

    assert first_count == second_count
    assert rows_after_first == rows_after_second  # nicio duplicare la repornire

@requires_corpus
def test_no_unfanged_urls_in_db(tmp_path: Path) -> None:
    """Criteriul 8.2 (I6): niciun URL nedefanged in DB - orice URL stocat
    trebuie sa fie in forma hxxp[://]... , niciodata http://... clicabil."""

    db_path = tmp_path / "test_defang.sqlite3"
    init_db(db_path)
    corpus_dir = Path(__file__).resolve().parents[1] / "corpus" / "eml"
    ingest_corpus(corpus_dir)

    session = get_session()
    reports = list_reports(session)
    session.close()

    assert len(reports) > 0, "corpusul nu a produs niciun raport - verifica ca ai fisiere .eml"

    for row in reports:
        urls = json.loads(row.defanged_urls_json)
        for url in urls:
            assert "http://" not in url, f"{row.file_name}: URL nedefanged gasit: {url}"
            assert "https://" not in url, f"{row.file_name}: URL nedefanged gasit: {url}"    