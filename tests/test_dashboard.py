"""Dashboard-ul, pe baza de date reala din fixture-ul de test.

Ce se verifica aici sunt exact lucrurile care pana acum pareau ca merg:
butoanele care raspundeau "succes" fara sa salveze nimic, filtrele care nu aveau
ce filtra, si statusul care disparea la refresh.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from triage import db
from triage.dashboard.app import app
from triage.db import session
from triage.pipeline import ingest_bytes

client = TestClient(app)

PHISHING = (
    b"From: Atacator <rau@evil-domain.example>\n"
    b"To: coleg@exemplu.ro\n"
    b"Subject: Contul dumneavoastra\n"
    b"Authentication-Results: mx.exemplu.ro; spf=fail\n"
    b"\n"
    b"Confirmati contul aici: https://rau.example/login\n"
)

SIMULARE = (
    b"From: SCAN <hp@notificaton.online>\n"
    b"To: coleg@exemplu.ro\n"
    b"Subject: Document scanat\n"
    b"In-Reply-To: <camp-1@mta1.cybereadysmtp.com>\n"
    b"\n"
    b"Aveti un document nou.\n"
)


def _seed() -> int:
    report = ingest_bytes(PHISHING)
    assert report is not None
    return report.id


def _status(report_id: int) -> str:
    with session() as s:
        report = db.get_report(s, report_id)
        assert report is not None
        return report.status


# ---------------------------------------------------------------------------
# Rute
# ---------------------------------------------------------------------------


def test_healthz() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_coada_goala_explica_ce_urmeaza() -> None:
    """Starea goala trebuie sa invete interfata, nu sa spuna 'nimic aici'."""
    response = client.get("/")
    assert response.status_code == 200
    assert "Coada este goală" in response.text
    assert "Rulează prima ingestie" in response.text


def test_coada_arata_raportarile() -> None:
    _seed()
    response = client.get("/")
    assert response.status_code == 200
    assert "Contul dumneavoastra" in response.text
    assert "Periculos" in response.text


def test_detaliul_arata_dovezile() -> None:
    report_id = _seed()
    response = client.get(f"/report/{report_id}")
    assert response.status_code == 200
    assert "AUTH_FAILURE" in response.text


def test_detaliu_inexistent_da_404() -> None:
    assert client.get("/report/9999").status_code == 404


def test_stats_fara_date() -> None:
    response = client.get("/stats")
    assert response.status_code == 200
    assert "Încă nu există date" in response.text


# ---------------------------------------------------------------------------
# Actiunile analistului - F1
# ---------------------------------------------------------------------------


def test_marcheaza_trimis_chiar_salveaza() -> None:
    """Butonul raspundea 'Actiune inregistrata cu succes' si nu salva nimic.
    Un mesaj de succes mincinos e mai rau decat o eroare."""
    report_id = _seed()
    response = client.post(f"/report/{report_id}/action", data={"action": "mark_sent"})

    assert response.status_code == 200  # dupa redirect
    assert _status(report_id) == "SENT"


def test_escaleaza_chiar_salveaza() -> None:
    report_id = _seed()
    client.post(f"/report/{report_id}/action", data={"action": "escalate"})
    assert _status(report_id) == "ESCALATED"


def test_actiunea_necunoscuta_nu_minte() -> None:
    report_id = _seed()
    response = client.post(f"/report/{report_id}/action", data={"action": "orice"})
    assert "Nu s-a schimbat nimic" in response.text
    assert _status(report_id) == "NEW"


def test_salvarea_draftului_persista() -> None:
    report_id = _seed()
    client.post(
        f"/report/{report_id}/action",
        data={"action": "save_draft", "final_draft": "Text scris de analist."},
    )
    assert "Text scris de analist." in client.get(f"/report/{report_id}").text


def test_corectia_de_verdict_persista_la_refresh() -> None:
    """Pana acum corectia disparea imediat ce se trimitea raspunsul."""
    report_id = _seed()
    client.post(
        f"/report/{report_id}/action",
        data={"action": "override_verdict", "corrected_verdict": "SPAM"},
    )

    detail = client.get(f"/report/{report_id}").text
    assert "corectat din Periculos" in detail

    with session() as s:
        report = db.get_report(s, report_id)
        assert report is not None
        assert report.verdict == "MALICIOUS", "verdictul automat nu se pierde"
        assert report.effective_verdict == "SPAM"


def test_verdict_invalid_e_ignorat() -> None:
    report_id = _seed()
    client.post(
        f"/report/{report_id}/action",
        data={"action": "override_verdict", "corrected_verdict": "INVENTAT"},
    )
    with session() as s:
        report = db.get_report(s, report_id)
        assert report is not None
        assert report.verdict_override is None


def test_actiunea_pe_un_raport_inexistent_da_404() -> None:
    assert client.post("/report/9999/action", data={"action": "mark_sent"}).status_code == 404


# ---------------------------------------------------------------------------
# Filtre si actiuni in masa - F2
# ---------------------------------------------------------------------------


def test_filtrarea_dupa_status() -> None:
    malicious = _seed()
    ingest_bytes(SIMULARE)
    client.post(f"/report/{malicious}/action", data={"action": "escalate"})

    escaladate = client.get("/?status=ESCALATED").text
    assert "Contul dumneavoastra" in escaladate
    assert "Document scanat" not in escaladate


def test_filtrarea_dupa_verdict() -> None:
    _seed()
    ingest_bytes(SIMULARE)

    simulari = client.get("/?verdict=SIMULATION").text
    assert "Document scanat" in simulari
    assert "Contul dumneavoastra" not in simulari


def test_filtru_fara_rezultate_ofera_iesirea() -> None:
    _seed()
    response = client.get("/?status=SENT")
    assert "Niciun raport pe filtrul acesta" in response.text
    assert "Arată toate raportările" in response.text


def test_actiunea_in_masa_persista() -> None:
    first = _seed()
    second = ingest_bytes(SIMULARE)
    assert second is not None

    client.post(
        "/bulk-action",
        data={"bulk_status": "SENT", "selected_ids": [str(first), str(second.id)]},
    )

    assert _status(first) == "SENT"
    assert _status(second.id) == "SENT"


def test_status_in_masa_invalid_e_respins() -> None:
    response = client.post("/bulk-action", data={"bulk_status": "INVENTAT"})
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Statistici - F3
# ---------------------------------------------------------------------------


def test_stats_arata_distributia_si_corectiile() -> None:
    report_id = _seed()
    ingest_bytes(SIMULARE)
    client.post(
        f"/report/{report_id}/action",
        data={"action": "override_verdict", "corrected_verdict": "SPAM"},
    )

    page = client.get("/stats").text
    assert "Distribuția verdictelor" in page
    assert "Ce se corectează" in page
    assert "Analizorul a spus" in page


# ---------------------------------------------------------------------------
# Securitate - sectiunea 4.2
# ---------------------------------------------------------------------------


def test_dashboardul_nu_randeaza_html_din_mail() -> None:
    raw = (
        b"From: rau@evil.example\n"
        b"To: coleg@exemplu.ro\n"
        b"Subject: <script>alert(1)</script>\n"
        b'Content-Type: text/html; charset=utf-8\n'
        b"\n"
        b'<b>ingrosat</b><img src=x onerror="alert(1)">\n'
    )
    report = ingest_bytes(raw)
    assert report is not None

    page = client.get(f"/report/{report.id}").text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert "onerror=" not in page


def test_niciun_url_clicabil_in_pagina() -> None:
    report_id = _seed()
    page = client.get(f"/report/{report_id}").text
    body = page[page.index("Linkuri") :]
    assert "https://rau.example" not in body
    assert "hxxps[://]rau[.]example/login" in body


def test_ingestia_din_dashboard_e_idempotenta(tmp_path: object) -> None:
    client.post("/ingest")
    with session() as s:
        first = len(db.list_reports(s))
    client.post("/ingest")
    with session() as s:
        assert len(db.list_reports(s)) == first
