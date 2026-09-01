from __future__ import annotations

from unittest.mock import patch
from fastapi.testclient import TestClient
from triage.dashboard.app import app
from triage.dashboard.app import load_real_reports

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


def test_healthz() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_queue_page() -> None:
    with patch("triage.dashboard.app.load_real_reports", return_value=MOCK_REPORTS):
        response = client.get("/")
        assert response.status_code == 200
        assert "Test Phishing Subject" in response.text


def test_report_detail_found() -> None:
    with patch("triage.dashboard.app.load_real_reports", return_value=MOCK_REPORTS):
        response = client.get("/report/1")
        assert response.status_code == 200
        assert "Test Phishing Subject" in response.text


def test_report_detail_not_found() -> None:
    with patch("triage.dashboard.app.load_real_reports", return_value=MOCK_REPORTS):
        response = client.get("/report/999")
        assert response.status_code == 404

def test_load_real_reports_execution() -> None:
    # Ruleaza functia direct pentru a acoperi liniile de procesare corpus
    reports = load_real_reports()
    assert isinstance(reports, list)