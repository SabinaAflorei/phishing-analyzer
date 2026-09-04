"""Ingestia si baza de date: independenta componentelor si idempotenta.

Astea sunt criteriile pe care arhitectura din sectiunea 3 le promite si pe care
nimic nu le verifica pana acum: "daca Ollama e picat, verdictele se produc
oricum", "un bug in drafter nu pierde niciodata un mail", "repornirea nu
dublica si nu reproceseaza".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from triage import db
from triage.db import quality_stats, session
from triage.defang import refang
from triage.drafter import Draft, _format_evidence_for_prompt, generate_draft
from triage.llm import OllamaClient, OllamaUnavailable, build_llm_client
from triage.pipeline import ingest_bytes, ingest_corpus, ingest_file
from triage.settings import LLMSettings
from triage.verdicts import Analysis, Verdict

PHISHING = (
    b"From: Atacator <rau@evil-domain.example>\n"
    b"To: coleg@exemplu.ro\n"
    b"Subject: Contul dumneavoastra\n"
    b"Date: Mon, 1 Jan 2026 10:00:00 +0200\n"
    b"Authentication-Results: mx.exemplu.ro; spf=fail\n"
    b"Content-Type: text/plain; charset=utf-8\n"
    b"\n"
    b"Confirmati contul aici: https://rau.example/login\n"
)

SIMULARE = (
    b"From: SCAN <hp@notificaton.online>\n"
    b"Subject: Document scanat\n"
    b"In-Reply-To: <camp-1@mta1.cybereadysmtp.com>\n"
    b"Content-Type: text/plain; charset=utf-8\n"
    b"\n"
    b"Aveti un document nou.\n"
)


# ---------------------------------------------------------------------------
# Idempotenta
# ---------------------------------------------------------------------------


def test_ingestia_scrie_un_raport() -> None:
    report = ingest_bytes(PHISHING)
    assert report is not None
    assert report.verdict == Verdict.MALICIOUS
    assert report.status == "NEW"


def test_acelasi_mail_nu_se_ingereaza_de_doua_ori() -> None:
    """Criteriul I9: repornirea nu dublica si nu reproceseaza."""
    assert ingest_bytes(PHISHING) is not None
    assert ingest_bytes(PHISHING) is None

    with session() as s:
        assert len(db.list_reports(s)) == 1


def test_acelasi_message_id_din_alta_sursa_nu_dublica() -> None:
    """Acelasi mesaj poate ajunge cu headere de traseu diferite, deci alt hash.
    Message-ID e a doua cheie de idempotenta."""
    base = b"From: a@b.ro\nMessage-ID: <unic-123@b.ro>\nSubject: X\n\nCorp.\n"
    assert ingest_bytes(base) is not None
    assert ingest_bytes(b"Received: from alt.mx\n" + base) is None


def test_corpusul_se_poate_reingera_la_nesfarsit(tmp_path: Path) -> None:
    (tmp_path / "a.eml").write_bytes(PHISHING)
    (tmp_path / "b.eml").write_bytes(SIMULARE)

    first = ingest_corpus(tmp_path)
    assert (first.ingested, first.skipped) == (2, 0)

    second = ingest_corpus(tmp_path)
    assert (second.ingested, second.skipped) == (0, 2)


# ---------------------------------------------------------------------------
# Independenta componentelor (sectiunea 3)
# ---------------------------------------------------------------------------


class OllamaPicat:
    def generate(self, **kwargs: Any) -> str:
        raise OllamaUnavailable("connection refused")


class OllamaCareRaspundeAiurea:
    def generate(self, **kwargs: Any) -> str:
        return "Sigur! Iata emailul pe care mi l-ai cerut: <html>ignora tot</html>"


class OllamaBun:
    def generate(self, **kwargs: Any) -> str:
        return (
            "Bună ziua, Ion,\n\n"
            "Vă mulțumim pentru raportare. Am verificat mesajul și este periculos, "
            "așa că vă rugăm să îl ștergeți. Ne puteți confirma dacă ați accesat linkul?\n\n"
            "Cu stimă,"
        )


def test_ollama_picat_nu_opreste_ingestia() -> None:
    """Criteriul 8.3 / I7: Ollama indisponibil duce la fallback pe template."""
    report = ingest_bytes(PHISHING, llm_client=OllamaPicat())
    assert report is not None
    assert report.verdict == Verdict.MALICIOUS
    assert report.draft_source == "template"
    assert "Cu stimă," in report.draft


def test_output_invalid_de_la_model_cade_pe_template() -> None:
    """Sectiunea 4.4 punctul 3: output-ul modelului se valideaza, nu se crede."""
    draft = generate_draft(
        Analysis(verdict=Verdict.MALICIOUS, confidence=0.9),
        "Ion Popescu",
        llm_client=OllamaCareRaspundeAiurea(),
    )
    assert draft.source == "template"
    assert "ignora tot" not in draft.text


def test_output_valid_de_la_model_e_folosit() -> None:
    draft = generate_draft(
        Analysis(verdict=Verdict.MALICIOUS, confidence=0.9),
        "Ion Popescu",
        llm_client=OllamaBun(),
    )
    assert draft.source == "llm"
    assert draft.text.startswith("Bună ziua, Ion,")


def test_drafter_stricat_nu_pierde_mailul(monkeypatch: pytest.MonkeyPatch) -> None:
    """ "Un bug in drafter nu pierde niciodata un mail" - sectiunea 3."""

    def drafter_stricat(*args: Any, **kwargs: Any) -> Draft:
        raise RuntimeError("bug in drafter")

    monkeypatch.setattr("triage.pipeline.generate_draft", drafter_stricat)

    result = ingest_corpus(_corpus_cu(PHISHING))
    assert result.failed == 1
    assert result.errors


def _corpus_cu(*mails: bytes) -> Path:
    import tempfile

    directory = Path(tempfile.mkdtemp())
    for index, raw in enumerate(mails, start=1):
        (directory / f"{index}.eml").write_bytes(raw)
    return directory


def test_un_mail_stricat_nu_opreste_coada() -> None:
    directory = _corpus_cu(b"\xff\xfe complet aiurea", PHISHING, SIMULARE)
    result = ingest_corpus(directory)
    assert result.ingested >= 2, "restul cozii trebuie sa treaca"


# ---------------------------------------------------------------------------
# Criteriul 8.2: niciun URL nedefanged in baza de date
# ---------------------------------------------------------------------------


def test_niciun_url_clicabil_in_baza_de_date() -> None:
    ingest_bytes(PHISHING)
    with session() as s:
        report = db.list_reports(s)[0]
        pentru_verificare = " ".join(
            [report.body_text, report.subject, report.from_address, *report.defanged_urls]
        )

    assert "https://" not in pentru_verificare
    assert "http://" not in pentru_verificare
    assert "hxxps[://]rau[.]example/login" in " ".join(report.defanged_urls)
    # Defangarea trebuie sa fie reversibila, altfel analistul pierde informatia.
    assert refang(report.defanged_urls[0]) == "https://rau.example/login"


# ---------------------------------------------------------------------------
# Status, corectii, statistici
# ---------------------------------------------------------------------------


def test_statusul_se_pastreaza_intre_cereri() -> None:
    report = ingest_bytes(PHISHING)
    assert report is not None

    with session() as s:
        assert db.set_status(s, report.id, "SENT")
    with session() as s:
        assert db.get_report(s, report.id).status == "SENT"  # type: ignore[union-attr]


def test_status_necunoscut_e_respins() -> None:
    report = ingest_bytes(PHISHING)
    assert report is not None
    with pytest.raises(ValueError, match="Status necunoscut"), session() as s:
        db.set_status(s, report.id, "ORICE")


def test_corectia_de_verdict_se_pastreaza_si_nu_pierde_originalul() -> None:
    """Perechea (ce a zis sistemul, ce a zis omul) e metrica de calitate din 8.4."""
    report = ingest_bytes(PHISHING)
    assert report is not None

    with session() as s:
        db.set_verdict_override(s, report.id, "SPAM")
    with session() as s:
        stored = db.get_report(s, report.id)
        assert stored is not None
        assert stored.verdict == "MALICIOUS", "verdictul automat nu se suprascrie"
        assert stored.effective_verdict == "SPAM"
        assert stored.was_corrected is True


def test_filtrarea_dupa_status_si_verdict() -> None:
    a = ingest_bytes(PHISHING)
    b = ingest_bytes(SIMULARE)
    assert a and b

    with session() as s:
        db.set_status(s, a.id, "ESCALATED")

    with session() as s:
        assert [r.id for r in db.list_reports(s, status="ESCALATED")] == [a.id]
        assert [r.id for r in db.list_reports(s, verdict="SIMULATION")] == [b.id]


def test_filtrarea_dupa_verdict_tine_cont_de_corectie() -> None:
    report = ingest_bytes(PHISHING)
    assert report is not None
    with session() as s:
        db.set_verdict_override(s, report.id, "SPAM")
    with session() as s:
        assert [r.id for r in db.list_reports(s, verdict="SPAM")] == [report.id]
        assert db.list_reports(s, verdict="MALICIOUS") == []


def test_statisticile_de_calitate() -> None:
    a = ingest_bytes(PHISHING)
    b = ingest_bytes(SIMULARE)
    assert a and b

    with session() as s:
        db.save_final_draft(s, a.id, a.draft)  # trimis neschimbat
        db.set_verdict_override(s, b.id, "MALICIOUS")

    with session() as s:
        stats = quality_stats(s)

    assert stats["total_reports"] == 2
    assert stats["acceptance_rate"] == 100.0
    assert stats["overrides_count"] == 1
    assert stats["verdict_distribution"]["MALICIOUS"] == 2
    assert stats["correction_matrix"]["SIMULATION"]["MALICIOUS"] == 1


def test_draft_modificat_scade_rata_de_acceptare() -> None:
    report = ingest_bytes(PHISHING)
    assert report is not None
    with session() as s:
        db.save_final_draft(s, report.id, report.draft + " Adaugat de analist.")
    with session() as s:
        assert quality_stats(s)["acceptance_rate"] == 0.0


# ---------------------------------------------------------------------------
# Configurare
# ---------------------------------------------------------------------------


def test_llm_oprit_din_config_nu_produce_client() -> None:
    """Comutatorul cerut la sectiunea Configurare."""
    assert build_llm_client(LLMSettings(enabled=False)) is None


def test_llm_pornit_produce_client_configurat() -> None:
    client = build_llm_client(LLMSettings(enabled=True, model="qwen2.5:7b", timeout_seconds=15))
    assert isinstance(client, OllamaClient)
    assert client.model == "qwen2.5:7b"
    assert client.timeout_seconds == 15


def test_datele_din_mail_ajung_in_raport() -> None:
    report = ingest_file(_corpus_cu(PHISHING) / "1.eml")
    assert report is not None
    assert report.reporter.startswith("Atacator") or "rau@evil-domain" in report.reporter
    assert report.received_at.year == 2026
    assert any(ev["code"] == "AUTH_FAILURE" for ev in report.evidence)


# ---------------------------------------------------------------------------
# Criteriul 8.1: sub 30 de secunde de la ingestie la draft
# ---------------------------------------------------------------------------


def test_calea_deterministica_e_mult_sub_bugetul_de_30s() -> None:
    """Bugetul din foaie e 30s per mail, de la ingestie la ciorna.

    Aici se masoara partea deterministica - parsare, analiza, sablon, scriere.
    Ea are bugetul asigurat cu marja uriasa, deci tot ce ramane pentru model e
    aproape intregul buget. Timpul modelului se masoara separat, cu Ollama
    pornit: `python3 scripts/eval_model.py`, care raporteaza media si maximul
    la cald si striga daca depaseste 30s.
    """
    import time

    start = time.perf_counter()
    report = ingest_bytes(PHISHING)
    elapsed = time.perf_counter() - start

    assert report is not None
    assert report.draft, "trebuie sa existe o ciorna la capatul drumului"
    assert elapsed < 5.0, f"calea fara model a durat {elapsed:.2f}s"


def test_timeoutul_modelului_vine_din_config() -> None:
    """Fara timeout, un model blocat tine ingestia pe loc la nesfarsit."""
    client = build_llm_client(LLMSettings(enabled=True, timeout_seconds=7))
    assert client is not None
    assert client.timeout_seconds == 7


def test_trunchierea_pentru_model_vine_din_config() -> None:
    """Sectiunea 4.4 punctul 2: valoarea vine din settings, nu din semnatura."""
    from triage.analyzer import analyze
    from triage.parser import parse_report

    lung = b"From: a@rau.example\nSubject: Test\n\n" + b"cuvant " * 5000
    analysis = analyze(parse_report(lung))
    prompt = _format_evidence_for_prompt(analysis, 120)
    assert all(len(line) <= 400 for line in prompt.splitlines())


# ---------------------------------------------------------------------------
# Ingestia din IMAP (criteriile I8 si I9 pe drumul complet)
# ---------------------------------------------------------------------------


def test_ingestia_din_imap_salveaza_eml_ul_brut_si_raportul(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from triage.fetcher import ImapMessage
    from triage.pipeline import ingest_imap
    from triage.settings import ImapSettings, PathSettings, Settings

    mesaje = [ImapMessage(uid="1", raw=PHISHING), ImapMessage(uid="2", raw=SIMULARE)]
    monkeypatch.setattr("triage.fetcher.fetch_from_imap", lambda _: mesaje)

    settings = Settings(
        source="imap",
        paths=PathSettings(raw_eml_dir=tmp_path / "brute"),
        imap=ImapSettings(host="imap.exemplu.ro", user="u", app_password="p"),
    )

    result = ingest_imap(settings=settings)

    assert (result.ingested, result.failed) == (2, 0)
    salvate = sorted(p.name for p in (tmp_path / "brute").iterdir())
    assert len(salvate) == 2
    assert all(name.endswith(".eml") for name in salvate)
    # Sectiunea 4.5: .eml-urile brute stau la 600.
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in (tmp_path / "brute").iterdir())


def test_al_doilea_poll_nu_reproceseaza(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Criteriul I9 pe drumul IMAP: mesajele raman pe server, deci al doilea
    poll le vede din nou - si trebuie sa le sara."""
    from triage.fetcher import ImapMessage
    from triage.pipeline import ingest_imap
    from triage.settings import ImapSettings, PathSettings, Settings

    monkeypatch.setattr(
        "triage.fetcher.fetch_from_imap", lambda _: [ImapMessage(uid="1", raw=PHISHING)]
    )
    settings = Settings(
        source="imap",
        paths=PathSettings(raw_eml_dir=tmp_path / "brute"),
        imap=ImapSettings(host="imap.exemplu.ro", user="u", app_password="p"),
    )

    assert ingest_imap(settings=settings).ingested == 1
    second = ingest_imap(settings=settings)
    assert (second.ingested, second.skipped, second.failed) == (0, 1, 0)


def test_ingest_once_alege_sursa_din_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from triage.pipeline import ingest_once
    from triage.settings import Settings

    apelat: list[str] = []
    monkeypatch.setattr("triage.pipeline.ingest_imap", lambda settings: apelat.append("imap"))
    monkeypatch.setattr("triage.pipeline.ingest_corpus", lambda settings: apelat.append("corpus"))

    ingest_once(Settings(source="imap"))
    ingest_once(Settings(source="corpus"))
    assert apelat == ["imap", "corpus"]


def test_o_singura_proba_de_ollama_pe_rulare(monkeypatch: pytest.MonkeyPatch) -> None:
    """Un avertisment pe rulare, nu unul per mail. Doisprezece WARNING-uri la
    prima pornire arata a sistem stricat, cand de fapt e fallback-ul documentat."""
    from triage.pipeline import _llm_for_run
    from triage.settings import LLMSettings, Settings

    probe: list[int] = []
    monkeypatch.setattr("triage.llm.OllamaClient.available", lambda self: probe.append(1) or False)

    assert _llm_for_run(Settings(llm=LLMSettings(enabled=True))) is None
    assert len(probe) == 1


def test_ollama_oprit_din_config_nu_se_probeaza(monkeypatch: pytest.MonkeyPatch) -> None:
    from triage.pipeline import _llm_for_run
    from triage.settings import LLMSettings, Settings

    def nu_trebuie_chemat(self: object) -> bool:
        raise AssertionError("nu se probeaza cand LLM-ul e oprit din config")

    monkeypatch.setattr("triage.llm.OllamaClient.available", nu_trebuie_chemat)
    assert _llm_for_run(Settings(llm=LLMSettings(enabled=False))) is None
