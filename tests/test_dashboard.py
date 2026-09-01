from __future__ import annotations

from fastapi.testclient import TestClient
from triage.dashboard.app import app

client = TestClient(app)


def test_healthz() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_queue_page() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Triaj raportari phishing" in response.text
    # Verificare existenta elementului mock în tabel
    assert "MALICIOUS" in response.text


def test_report_detail_not_found() -> None:
    response = client.get("/report/non_existent_id")
    assert response.status_code == 404


def test_report_detail_found() -> None:
    response = client.get("/report/rep-101")
    assert response.status_code == 200