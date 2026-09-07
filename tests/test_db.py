from pathlib import Path

from triage.db import get_session, init_db, list_reports
from triage.ingest import ingest_corpus


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