from __future__ import annotations

from unittest.mock import patch
from fastapi.testclient import TestClient
from triage.dashboard.app import app
from fastapi.testclient import TestClient
from triage.dashboard.app import app
from triage.db import get_session, list_reports, init_db, get_report
from triage.ingest import ingest_corpus
from pathlib import Path


client = TestClient(app)

MOCK_REPORTS = [
    {
        "id": "1",
        "file_name": "01_cyberready_forward.eml",
        "subject": "Test Phishing Subject",
        "from_address": "test@example.com",
        "reporter": "test@example.com",
        "received_at": "2026-08-30 10:00",
        "verdict": "MALICIOUS",
        "confidence": 0.95,
        "status": "NEW",
        "evidence": ["SPF Failure"],
        "defanged_urls": ["hxxp[://]bad[.]com"],
        "draft": "Ciorna de raspuns",
    }
]

CORPUS_DIR= Path(__file__).resolve().parents[1] / "corpus" / "eml"
def db_with_corpus(tmp_path: Path)-> None:
    """ Initializeaza baza si ingerare corpus."""
    db_path=tmp_path / "test.sqlite3"
    init_db(db_path)
    ingest_corpus(CORPUS_DIR)

def test_healthz() -> None:
    client= TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_queue_page(tmp_path:Path) -> None:
    db_with_corpus(tmp_path)
    client= TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    session=get_session()
    reports=list_reports(session)
    session.close()
    assert len(reports)>0
    assert reports[0].subject in response.text or reports[0].file_name in response.text


def test_report_detail_found(tmp_path: Path) -> None:
    db_with_corpus(tmp_path)

    session = get_session()
    report_id = list_reports(session)[0].id
    session.close()

    client = TestClient(app)
    response = client.get(f"/report/{report_id}")

    assert response.status_code == 200


def test_report_detail_not_found(tmp_path: Path) -> None:
    db_with_corpus(tmp_path)

    client = TestClient(app)
    response = client.get("/report/nu_exista_id")

    assert response.status_code == 404


def test_mark_sent_persists_status(tmp_path: Path) -> None:
    db_with_corpus(tmp_path)

    session = get_session()
    report_id = list_reports(session)[0].id
    session.close()

    client = TestClient(app)
    response = client.post(f"/report/{report_id}/action", data={"action": "mark_sent"})
    assert response.status_code == 200

    session = get_session()
    row = get_report(session, report_id)
    assert row is not None
    assert row.status == "SENT"
    session.close()


def test_escalate_persists_status(tmp_path: Path) -> None:
    db_with_corpus(tmp_path)

    session = get_session()
    report_id = list_reports(session)[0].id
    session.close()

    client = TestClient(app)
    response = client.post(f"/report/{report_id}/action", data={"action": "escalate"})
    assert response.status_code == 200

    session = get_session()
    row = get_report(session, report_id)
    assert row is not None
    assert row.status == "ESCALATED"
    session.close()


def test_verdict_override_persists_and_reflects_on_reload(tmp_path: Path) -> None:
    db_with_corpus(tmp_path)

    session = get_session()
    report_id = list_reports(session)[0].id
    session.close()

    client = TestClient(app)
    client.post(
        f"/report/{report_id}/action",
        data={"action": "override_verdict", "corrected_verdict": "LEGITIMATE"},
    )

    response = client.get(f"/report/{report_id}")
    assert "LEGITIMATE" in response.text


def test_bulk_action_updates_multiple_statuses(tmp_path: Path) -> None:
    db_with_corpus(tmp_path)

    session = get_session()
    report_ids = [r.id for r in list_reports(session)[:2]]
    session.close()

    client = TestClient(app)
    response = client.post(
        "/bulk-action",
        data={"selected_ids": report_ids, "bulk_status": "ESCALATED"},
    )
    assert response.status_code == 200

    session = get_session()
    for report_id in report_ids:
        row = get_report(session, report_id)
        assert row is not None
        assert row.status == "ESCALATED"
    session.close()


def test_stats_page_loads() -> None:
    client = TestClient(app)
    response = client.get("/stats")
    assert response.status_code == 200

def test_stats_includes_verdict_distribution_and_corrections(tmp_path: Path) -> None:
    db_with_corpus(tmp_path)

    session = get_session()
    report_id = list_reports(session)[0].id
    original_verdict = list_reports(session)[0].verdict
    session.close()

    client = TestClient(app)
    client.post(
        f"/report/{report_id}/action",
        data={"action": "override_verdict", "corrected_verdict": "LEGITIMATE"},
    )

    from triage.dashboard.feedback_store import get_feedback_stats
    stats = get_feedback_stats()

    assert "verdict_distribution" in stats
    assert "corrections_by_category" in stats
    assert original_verdict in stats["corrections_by_category"]    