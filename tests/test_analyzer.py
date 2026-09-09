from __future__ import annotations

import re
from pathlib import Path

import pytest

from triage.analyzer import (
    MALICIOUS_THRESHOLD,
    SIGNAL_WEIGHT,
    analyze,
    is_cybeready_simulation,
    score_of,
)
from triage.parser import ParsedAttachment, ParsedEmail, ParsedLink, ReportKind
from triage.verdicts import Severity, Verdict


def codes(parsed: ParsedEmail) -> set[str]:
    return {ev.code for ev in analyze(parsed).evidence}


@pytest.fixture(autouse=True)
def _domenii_fixe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Testele din acest fisier isi fixeaza singure domeniile companiei.

    Cazurile de mai jos sunt scrise pe `exemplu.ro`. Analizorul isi citeste
    domeniile din `config/company_domains.yaml`, care e in .gitignore si contine
    domeniile REALE pe masina unui operator. Fara fixarea de aici, suita devenea
    rosie in clipa in care cineva configura sistemul pentru productie - un test
    de unitate nu are voie sa depinda de configuratia locala a masinii.

    Corpusul ramane pe configuratia ambientala: acolo mesajele si domeniile
    trebuie sa vina din aceeasi lume ca sa aiba sens.
    """
    from triage import analyzer

    monkeypatch.setattr(
        analyzer, "COMPANY_OWNED", {"exemplu.ro", "intern.exemplu.ro", "exemplu.com"}
    )
    monkeypatch.setattr(
        analyzer,
        "MAIL_INFRA",
        {"mail1.exemplu.ro", "mx01.exemplu.com", "exc00aa01p.intern.exemplu.ro"},
    )
    monkeypatch.setattr(
        analyzer,
        "TRUSTED_PARTNERS",
        {"microsoft.com", "atlassian.net", "furnizor-newsletter.ro", "ctce.ro"},
    )
    monkeypatch.setattr(analyzer, "REPORT_MAILBOX", "itsec@exemplu.ro")


# ---------------------------------------------------------------------------
# Autentificare
# ---------------------------------------------------------------------------


def test_analyze_auth_failure() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        auth_results="spf=fail (sender IP is 1.2.3.4)",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS
    assert result.confidence == 0.9


def test_analyze_legitimate() -> None:
    """Trece ca LEGITIMATE doar cu SPF, DKIM si DMARC pass, si fara alte semnale."""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="user@company.com",
        auth_results="spf=pass dkim=pass dmarc=pass",
    )
    assert analyze(parsed).verdict == Verdict.LEGITIMATE


def test_analyze_partial_auth_pass_goes_to_needs_review() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="user@company.com",
        auth_results="spf=pass dkim=pass dmarc=none",
    )
    assert analyze(parsed).verdict == Verdict.NEEDS_REVIEW


def test_analyze_missing_auth_results_goes_to_needs_review() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="user@company.com",
        auth_results="",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.NEEDS_REVIEW
    assert result.evidence[0].code == "INSUFFICIENT_EVIDENCE"


# ---------------------------------------------------------------------------
# CyberReady: domeniul singur nu e niciodata suficient
# ---------------------------------------------------------------------------

CYBEREADY_DOMENII = [
    "act-now-www.org",
    "admin-support.site",
    "business-insight.online",
    "cloud-mail.store",
    "contactmail.app",
    "do-not-reqly.com",
    "front-desk.site",
    "incoming-mail-msg.com",
    "info-alerts.tech",
    "notificaton.online",
    "ses.distributie-energie.ro",
]


@pytest.mark.parametrize("domain", CYBEREADY_DOMENII)
def test_domeniul_de_simulare_singur_nu_da_simulation(domain: str) -> None:
    """Lista de domenii e publica in repo. Cine o citeste poate pune domeniul in
    From-ul unui phishing real si ar primi raspunsul bland de simulare."""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address=f"simulation-test@{domain}",
        auth_results="spf=pass",
    )
    assert analyze(parsed).verdict != Verdict.SIMULATION


@pytest.mark.parametrize("domain", CYBEREADY_DOMENII)
def test_domeniu_plus_message_id_da_simulation(domain: str) -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address=f"simulation-test@{domain}",
        auth_results="spf=pass",
        in_reply_to="<abc@mta1.cybereadysmtp.com>",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.SIMULATION
    assert result.confidence == 1.0
    assert result.evidence[0].code == "CYBEREADY_SIMULATION"


def test_domeniu_plus_identitate_dkim_da_simulation() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="simulation-test@ses.distributie-energie.ro",
        auth_results="spf=pass header.i=@mta1.cybereadysmtp.com",
    )
    assert analyze(parsed).verdict == Verdict.SIMULATION


def test_domeniu_plus_ip_de_expeditie_da_simulation() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="hp@notificaton.online",
        received_chain=["from crsmtp.notificaton.online (99.80.130.134) by mx.exemplu.ro"],
    )
    assert analyze(parsed).verdict == Verdict.SIMULATION


def test_domeniu_plus_header_propriu_da_simulation() -> None:
    """Semnalul 4: headerele proprietare ale platformei (X-CRPS, X-Virtual-MTA)."""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="hp@notificaton.online",
        header_names=["from", "subject", "x-crps", "x-virtual-mta"],
    )
    assert analyze(parsed).verdict == Verdict.SIMULATION


def test_link_de_tracking_singur_nu_da_simulation_unui_strain() -> None:
    """Cel mai grav fals pozitiv de dinainte: un link catre inner.website,
    domeniu scris in config-ul public, dadea SIMULATION oricui."""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="attacker@totally-evil.tld",
        urls=["https://inner.website/landing/abc"],
    )
    assert analyze(parsed).verdict != Verdict.SIMULATION


def test_domeniu_de_simulare_plus_link_de_tracking_da_simulation() -> None:
    """Semnalul slab confirma un expeditor deja plauzibil - asta e rolul lui."""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="hp@notificaton.online",
        urls=["https://trck.cybeready.net/opentracking/1/mta1/x.gif"],
    )
    assert analyze(parsed).verdict == Verdict.SIMULATION


def test_forward_inline_prinde_simularea_prin_in_reply_to() -> None:
    """Cazul 01: headerele originale nu supravietuiesc forward-ului, dar
    In-Reply-To / References pastreaza Message-ID-ul platformei."""
    parsed = ParsedEmail(
        report_kind=ReportKind.FORWARD_INLINE,
        from_address="hp@notificaton.online",
        references="<camp-42@mta1.cybereadysmtp.com>",
        headers_from_body=True,
    )
    assert analyze(parsed).verdict == Verdict.SIMULATION


def test_spf_fail_anuleaza_fingerprint_ul_de_simulare() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="test@act-now-www.org",
        auth_results="spf=fail dkim=fail",
        in_reply_to="<abc@mta1.cybereadysmtp.com>",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS
    assert result.confidence == 0.9
    assert not is_cybeready_simulation(parsed)


def test_hostname_de_tracking_nu_se_potriveste_pe_sufix_de_text() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="hp@notificaton.online",
        urls=["https://inner.website.evil.ru/pagina"],
    )
    assert analyze(parsed).verdict != Verdict.SIMULATION


# ---------------------------------------------------------------------------
# Atasamente
# ---------------------------------------------------------------------------


def _att(filename: str, *, encrypted: bool = False) -> ParsedAttachment:
    return ParsedAttachment(
        filename=filename,
        sha256="1234567890abcdef",
        mime_type="application/octet-stream",
        size=1024,
        encrypted_archive=encrypted,
    )


@pytest.mark.parametrize(
    "filename", ["invoice.exe", "invoice.docm", "invoice.pdf.exe", "payload.iso", "disc.img"]
)
def test_atasamente_periculoase(filename: str) -> None:
    parsed = ParsedEmail(report_kind=ReportKind.UNKNOWN, attachments=[_att(filename)])
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS
    assert result.confidence == 0.95


@pytest.mark.parametrize(
    "filename", ["raport.xls.pdf", "poza.jpg.png", "contract.doc.docx", "factura.pdf"]
)
def test_dubla_extensie_inofensiva_nu_e_condamnata(filename: str) -> None:
    """Periculoasa e combinatia "pare document, dar e executabil". Un .pdf care
    urmeaza dupa .xls e doar un nume ciudat."""
    parsed = ParsedEmail(report_kind=ReportKind.UNKNOWN, attachments=[_att(filename)])
    assert analyze(parsed).verdict != Verdict.MALICIOUS


def test_arhiva_protejata_cu_parola_e_semnalata() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        attachments=[_att("acte.rar", encrypted=True)],
    )
    assert "ENCRYPTED_ARCHIVE" in codes(parsed)


# ---------------------------------------------------------------------------
# Domenii proprii, lookalike, homoglife
# ---------------------------------------------------------------------------


def test_mail_intern_prin_infra_proprie_nu_e_malicios() -> None:
    """Cel mai grav fals pozitiv de dinainte: domeniile proprii semanau intre
    ele, deci lookalike marca orice mail intern ca malitios."""
    for addr, host in (
        ("ceo@exemplu.com", "mx01.exemplu.com"),
        ("hr@exemplu.ro", "mail1.exemplu.ro"),
    ):
        parsed = ParsedEmail(
            report_kind=ReportKind.UNKNOWN,
            from_address=addr,
            received_chain=[f"from {host} by mx.exemplu.ro"],
            auth_results="spf=pass dkim=pass dmarc=pass",
        )
        assert analyze(parsed).verdict != Verdict.MALICIOUS, addr


def test_spoofing_de_domeniu_intern() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="ceo@exemplu.ro",
        received_chain=["from vps-217.reset-portal-energie.ru by mx.exemplu.ro"],
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS
    assert "INTERNAL_DOMAIN_SPOOF" in {ev.code for ev in result.evidence}


def test_spoofing_intern_nu_se_evalueaza_pe_lantul_gresit() -> None:
    """La un forward inline, From vine din corp iar Received e al colegului care
    a raportat. Comparatia intre ele raspunde la intrebarea gresita."""
    parsed = ParsedEmail(
        report_kind=ReportKind.FORWARD_INLINE,
        from_address="ceo@exemplu.ro",
        received_chain=["from mail.gmail.com by mx.exemplu.ro"],
        headers_from_body=True,
    )
    assert "INTERNAL_DOMAIN_SPOOF" not in codes(parsed)


def test_lookalike_de_domeniu_propriu() -> None:
    parsed = ParsedEmail(report_kind=ReportKind.UNKNOWN, from_address="ceo@exemplu.r0")
    assert "LOOKALIKE_DOMAIN" in codes(parsed)


def test_homoglif_chirilic_e_detectat() -> None:
    """Levenshtein nu prinde asta: distanta vizuala e 0, cea pe bytes e mare."""
    # "\u043e" e un O CHIRILIC, nu unul latin - exact tiparul pe care il vanam.
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="admin@micr\u043esoft.com",
    )
    assert "HOMOGLYPH_DOMAIN" in codes(parsed)


def test_punycode_e_detectat() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="admin@xn--micrsoft-o4a.com",
    )
    assert "PUNYCODE_DOMAIN" in codes(parsed)


def test_tld_de_risc_singur_nu_condamna() -> None:
    """Un TLD e un indiciu slab, nu o dovada. Varianta veche dadea MALICIOUS 0.9
    unui expeditor doar pentru ca era pe .online."""
    parsed = ParsedEmail(report_kind=ReportKind.UNKNOWN, from_address="news@furnizor.online")
    result = analyze(parsed)
    assert result.verdict != Verdict.MALICIOUS
    assert "HIGH_RISK_TLD" in {ev.code for ev in result.evidence}


# ---------------------------------------------------------------------------
# D1, D2, D4: consistenta headerelor
# ---------------------------------------------------------------------------


def test_reply_to_diferit_de_from() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="facturi@furnizor.ro",
        reply_to="atacator@gmail.com",
    )
    assert "REPLY_TO_MISMATCH" in codes(parsed)


def test_reply_to_pe_acelasi_domeniu_nu_e_semnal() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="facturi@furnizor.ro",
        reply_to="contact@mail.furnizor.ro",
    )
    assert "REPLY_TO_MISMATCH" not in codes(parsed)


def test_return_path_diferit_de_from() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="facturi@furnizor.ro",
        return_path="<bounce@rau.tld>",
    )
    assert "RETURN_PATH_MISMATCH" in codes(parsed)


def test_return_path_diferit_e_normal_pe_liste_de_mail() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="news@furnizor.ro",
        return_path="<bounce-123@esp.example>",
        header_names=["from", "list-unsubscribe"],
    )
    assert "RETURN_PATH_MISMATCH" not in codes(parsed)


def test_display_name_pretinde_alt_domeniu() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="atacator@rau.tld",
        from_display_name="Microsoft Support",
    )
    assert "DISPLAY_NAME_MISMATCH" in codes(parsed)


def test_display_name_cu_domeniu_scris_in_clar() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="atacator@rau.tld",
        from_display_name="facturi@exemplu.ro",
    )
    assert "DISPLAY_NAME_MISMATCH" in codes(parsed)


def test_display_name_potrivit_nu_e_semnal() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="support@microsoft.com",
        from_display_name="Microsoft Support",
    )
    assert "DISPLAY_NAME_MISMATCH" not in codes(parsed)


# ---------------------------------------------------------------------------
# D5: semnale de continut
# ---------------------------------------------------------------------------


def test_urgenta_artificiala() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        body_text="Contul dumneavoastră va fi suspendat în 24 de ore.",
    )
    assert "ARTIFICIAL_URGENCY" in codes(parsed)


def test_cerere_de_credentiale() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        body_text="Vă rugăm să vă confirmați contul introducând parola.",
    )
    assert "CREDENTIAL_REQUEST" in codes(parsed)


def test_discrepanta_intre_textul_linkului_si_href() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        links=[ParsedLink(text="www.banca-mea.ro", href="https://rau.tld/login")],
    )
    assert "LINK_TEXT_MISMATCH" in codes(parsed)


def test_link_care_duce_unde_scrie_nu_e_semnal() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        links=[ParsedLink(text="www.banca-mea.ro", href="https://banca-mea.ro/login")],
    )
    assert "LINK_TEXT_MISMATCH" not in codes(parsed)


# ---------------------------------------------------------------------------
# D6: coroborare
# ---------------------------------------------------------------------------


def test_semnalele_slabe_se_aduna_pana_la_prag() -> None:
    """Trei semnale medii care singure nu inseamna nimic ajung impreuna la
    MALICIOUS. Asta e coroborarea ceruta la 6.3."""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="secure@paypa1-verify.top",
        from_display_name="PayPal Security",
        reply_to="colect@gmail.com",
        return_path="<bounce@alt.tld>",
        subject="Cont suspendat - acționați acum",
        body_text="Contul expiră în 24 de ore. Confirmați contul cu parola dumneavoastră.",
    )
    result = analyze(parsed)
    assert score_of(result.evidence) >= MALICIOUS_THRESHOLD
    assert result.verdict == Verdict.MALICIOUS


def test_un_singur_semnal_mediu_nu_ajunge_la_malicious() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="facturi@furnizor.ro",
        reply_to="alt@gmail.com",
    )
    assert analyze(parsed).verdict == Verdict.NEEDS_REVIEW


def test_semnale_coroborate_sub_prag_dau_needs_review_cu_incredere_mai_mare() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="facturi@furnizor.ro",
        reply_to="alt@gmail.com",
        return_path="<bounce@third.tld>",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.NEEDS_REVIEW
    assert result.confidence == 0.6
    assert "CORROBORATED_SIGNALS" in {ev.code for ev in result.evidence}


def test_nepotrivirile_de_rutare_singure_nu_dau_malicious() -> None:
    """Marginea de jos a benzii de coroborare, pusa in cui.

    Reply-To + Return-Path + display-name nepotrivit inseamna doar ca mesajul e
    rutat altfel decat pare - forma pe care o are ORICE newsletter trimis printr-un
    furnizor de mail. Niciun semnal nu spune nimic despre continut: nu se cere
    nimic, nu se ascunde niciun link, nu e niciun atasament.

    La ponderile vechi trio-ul facea exact 1.00 si iesea MALICIOUS, adica "sterge
    mesajul, e periculos" trimis unui coleg pentru un mail de marketing. Testul
    exista ca sa nu se intoarca printr-o recalibrare facuta din alt motiv.
    """
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="stiri@buletin-informativ.ro",
        from_display_name="Newsletter ctce.ro",
        reply_to="raspuns@redactie.ro",
        return_path="<bounce-9931@mailer-furnizor.net>",
        subject="Buletinul saptamanii",
        body_text="Articolele saptamanii. Va puteti dezabona oricand.",
    )
    result = analyze(parsed)
    codes = {ev.code for ev in result.evidence}

    assert codes >= {"REPLY_TO_MISMATCH", "RETURN_PATH_MISMATCH", "DISPLAY_NAME_MISMATCH"}
    assert score_of(result.evidence) < MALICIOUS_THRESHOLD
    assert result.verdict != Verdict.MALICIOUS


def test_semnalele_de_continut_duc_peste_prag_fara_niciun_semnal_grav() -> None:
    """Marginea de sus: coroborarea CHIAR are voie sa ajunga la MALICIOUS.

    Forma cazului 08 din corpus - phishing de credentiale printr-un forward, unde
    Authentication-Results nu supravietuieste, deci nu exista niciun semnal
    CRITICAL sau HIGH. Verdictul se sustine din semnale de continut: numele afisat
    minte, linkul duce altundeva decat scrie, se cer datele de autentificare.

    Perechea cu testul de mai sus e ideea intreaga a sectiunii 6.3: nu conteaza
    CATE semnale sunt, conteaza daca vreunul spune ceva despre ce vrea mesajul de
    la om.
    """
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="office@securitate-conturi.info",
        from_display_name="Suport ctce.ro",
        subject="Contul dumneavoastra expira in 24 de ore",
        body_text="Confirmati contul si introduceti parola pentru a evita suspendarea.",
        links=[ParsedLink(text="ctce.ro/cont", href="https://securitate-conturi.info/login")],
    )
    result = analyze(parsed)
    severities = {ev.severity for ev in result.evidence}

    assert Severity.CRITICAL not in severities and Severity.HIGH not in severities
    assert score_of(result.evidence) >= MALICIOUS_THRESHOLD
    assert result.verdict == Verdict.MALICIOUS


def test_toate_codurile_de_semnal_au_pondere() -> None:
    """Un cod fara pondere ar conta 0 in tacere, adica ar fi cod mort."""
    from triage import analyzer

    used = set(re.findall(r'code="([A-Z_]+)"', Path(analyzer.__file__).read_text(encoding="utf-8")))
    assert used <= set(SIGNAL_WEIGHT), f"coduri fara pondere: {used - set(SIGNAL_WEIGHT)}"


# ---------------------------------------------------------------------------
# Clasificare
# ---------------------------------------------------------------------------


def test_newsletter_de_partener_de_incredere() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="newsletter@ctce.ro",
        subject="Newsletter JuristPRO",
        body_text="Noutăți legislative. Vă puteți dezabona oricând.",
        header_names=["from", "subject", "list-unsubscribe"],
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.LEGITIMATE
    assert result.confidence == 0.85


def test_marketing_nesolicitat_e_spam() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="contact@firma-necunoscuta.ro",
        subject="Invitație la simpozion",
        body_text="Vă invităm la conferința anuală. Dezabonare la finalul mesajului.",
    )
    assert analyze(parsed).verdict == Verdict.SPAM


def test_screenshot_only() -> None:
    parsed = ParsedEmail(report_kind=ReportKind.SCREENSHOT_ONLY)
    result = analyze(parsed)
    assert result.verdict == Verdict.NEEDS_REVIEW
    assert result.confidence == 0.5


# ---------------------------------------------------------------------------
# Robustete
# ---------------------------------------------------------------------------


def test_analyze_empty_from_address_goes_to_needs_review() -> None:
    parsed = ParsedEmail(report_kind=ReportKind.UNKNOWN, from_address="", auth_results="spf=pass")
    assert analyze(parsed).verdict == Verdict.NEEDS_REVIEW


def test_analyze_malformed_from_header() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="<<<invalid_email>>>",
        auth_results="spf=pass",
    )
    assert analyze(parsed).verdict == Verdict.NEEDS_REVIEW


def test_severitatea_si_ponderea_merg_impreuna() -> None:
    """Regula de aur a analizorului: nu poti scrie Severity.MEDIUM si obtine
    MALICIOUS dintr-un singur semnal."""
    for code, weight in SIGNAL_WEIGHT.items():
        if weight >= MALICIOUS_THRESHOLD:
            assert code in {"AUTH_FAILURE", "SUSPECT_ATTACHMENT", "INTERNAL_DOMAIN_SPOOF"}, code
