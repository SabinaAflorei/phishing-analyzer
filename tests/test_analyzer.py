from __future__ import annotations

import pytest
from triage.analyzer import analyze
from triage.parser import ParsedAttachment, ParsedEmail, ReportKind
from triage.verdicts import Verdict
from triage.analyzer import COMPANY_OWNED
from triage.analyzer import COMPANY_CONFIG

def test_analyze_cyberready_simulation() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="test@act-now-www.org",
        auth_results="spf=pass dkim=pass",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.SIMULATION
    assert result.confidence == 1.0


def test_analyze_spoofed_cybeready_domain_fails() -> None:
    """From falsificat cu un domeniu de simulare dar cu SPF fail NU trebuie să iasă SIMULATION."""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="test@act-now-www.org",
        auth_results="spf=fail dkim=fail",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS
    assert result.confidence == 0.8


def test_analyze_screenshot_only() -> None:
    parsed = ParsedEmail(report_kind=ReportKind.SCREENSHOT_ONLY)
    result = analyze(parsed)
    assert result.verdict == Verdict.NEEDS_REVIEW
    assert result.confidence == 0.5


def test_analyze_auth_failure() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        auth_results="spf=fail (sender IP is 1.2.3.4)",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS
    assert result.confidence == 0.8


def test_analyze_suspect_attachment() -> None:
    att = ParsedAttachment(
        filename="invoice.exe",
        sha256="1234567890abcdef",
        mime_type="application/x-msdownload",
        size=1024,
    )
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        attachments=[att],
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS
    assert result.confidence == 0.99


def test_analyze_macro_attachment() -> None:
    """Atașament cu macro (.docm)."""
    att = ParsedAttachment(
        filename="invoice.docm",
        sha256="1234567890abcdef",
        mime_type="application/vnd.ms-word.document.macroEnabled.12",
        size=2048,
    )
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        attachments=[att],
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS


def test_analyze_double_extension() -> None:
    """Atașament cu dublă extensie (ex: document.pdf.exe)."""
    att = ParsedAttachment(
        filename="invoice.pdf.exe",
        sha256="1234567890abcdef",
        mime_type="application/octet-stream",
        size=2048,
    )
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        attachments=[att],
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS


def test_analyze_legitimate() -> None:
    """Mailul trece ca LEGITIMATE doar dacă are SPF, DKIM și DMARC pass."""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="user@company.com",
        auth_results="spf=pass dkim=pass dmarc=pass",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.LEGITIMATE


def test_analyze_missing_auth_results_goes_to_needs_review() -> None:
    """Mail fără Authentication-Results trece automat în NEEDS_REVIEW."""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="user@company.com",
        auth_results="",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.NEEDS_REVIEW


@pytest.mark.parametrize(
    "cybeready_domain",
    [
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
    ],
)
def test_cybeready_simulation_domains(cybeready_domain: str) -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address=f"simulation-test@{cybeready_domain}",
        auth_results="spf=pass",
    )
    analysis = analyze(parsed)

    assert analysis.verdict == Verdict.SIMULATION
    assert analysis.confidence == 1.0
    assert analysis.evidence[0].code == "CYBEREADY_SIMULATION"


def test_cybeready_sensitive_domain_requires_extra_signals() -> None:
    parsed_spoofed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="simulation-test@ses.distributie-energie.ro",
        auth_results="spf=pass",
    )
    assert analyze(parsed_spoofed).verdict != Verdict.SIMULATION

    parsed_valid = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="simulation-test@ses.distributie-energie.ro",
        auth_results="spf=pass header.i=@mta1.cybereadysmtp.com",
    )
    assert analyze(parsed_valid).verdict == Verdict.SIMULATION

def test_analyze_empty_from_address_goes_to_needs_review() -> None:
    """Mail fără adresă From validează fallback-ul pe NEEDS_REVIEW."""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="",
        auth_results="spf=pass",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.NEEDS_REVIEW


def test_analyze_malformed_from_header() -> None:
    """Format de From neobișnuit sau malformat."""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="<<<invalid_email>>>",
        auth_results="spf=pass",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.NEEDS_REVIEW


def test_analyze_partial_auth_pass_goes_to_needs_review() -> None:
    """Pass pe SPF și DKIM, dar fără DMARC pass -> nu trece automat la LEGITIMATE."""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="user@company.com",
        auth_results="spf=pass dkim=pass dmarc=none",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.NEEDS_REVIEW

def test_reply_to_mismatch_blocks_auto_legitimate() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="webmail@distributie-energie.ro",
        reply_to="atacator@gmail.com",
        auth_results="spf=pass dkim=pass dmarc=pass",
    )
    result = analyze(parsed)
    assert result.verdict != Verdict.LEGITIMATE
    codes = {e.code for e in result.evidence}
    assert "REPLY_TO_MISMATCH" in codes


def test_return_path_mismatch_alone_does_not_force_malicious() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="webmail@distributie-energie.ro",
        return_path="bounce@esp-extern.com",
        auth_results="spf=pass dkim=pass dmarc=pass",
    )
    result = analyze(parsed)
    assert result.verdict != Verdict.MALICIOUS


def test_no_reply_to_no_mismatch() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="cineva@exemplu.ro",
        auth_results="spf=pass dkim=pass dmarc=pass",
    )
    result = analyze(parsed)
    codes = {e.code for e in result.evidence}
    assert "REPLY_TO_MISMATCH" not in codes
    assert "RETURN_PATH_MISMATCH" not in codes    

def test_encrypted_archive_is_malicious():
    att = ParsedAttachment(
        filename="factura.zip",
        sha256="abc123",
        mime_type="application/zip",
        size=2048,
        is_encrypted_archive=True,
    )
    parsed = ParsedEmail(report_kind=ReportKind.UNKNOWN, attachments=[att])
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS
    codes = {e.code for e in result.evidence}
    assert "ENCRYPTED_ARCHIVE" in codes
   


def _pick_owned_domain() -> str:
    if not COMPANY_OWNED:
        pytest.skip("COMPANY_OWNED e gol - company_domains.yaml lipseste sau nu are owned_domains")
    return sorted(COMPANY_OWNED)[0]


def test_homoglyph_domain_detected() -> None:
    """domeniu cu 'а' chirilic in loc de 'a' latin - vizual identic, Levenshtein=0""" # noqa: RUF002
    owned = _pick_owned_domain()
    if "a" not in owned:
        pytest.skip(f"domeniul de test '{owned}' nu contine 'a' latin de inlocuit")
    homoglyph_domain = owned.replace("a", "\u0430", 1)  # 'а' chirilic (U+0430)  # noqa: RUF003

    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address=f"webmail@{homoglyph_domain}",
        auth_results="spf=pass",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS
    codes = {e.code for e in result.evidence}
    assert "HOMOGLYPH_DOMAIN" in codes


def test_punycode_domain_decoded_and_checked() -> None:
    """xn--... trebuie decodat inainte de comparatie, nu tratat ca opac"""
    owned = _pick_owned_domain()
    if "a" not in owned:
        pytest.skip(f"domeniul de test '{owned}' nu contine 'a' latin de inlocuit")
    homoglyph_domain = owned.replace("a", "\u0430", 1)
    punycode_domain = homoglyph_domain.encode("idna").decode("ascii")

    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address=f"webmail@{punycode_domain}",
        auth_results="spf=pass",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS
    codes = {e.code for e in result.evidence}
    assert "HOMOGLYPH_DOMAIN" in codes


def test_legit_own_domain_not_flagged_as_homoglyph() -> None:
    """domeniul propriu real nu trebuie sa se auto-semnaleze"""
    owned = _pick_owned_domain()
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address=f"webmail@{owned}",
        auth_results="spf=pass dkim=pass dmarc=pass",
        received_chain=[f"from mail1.{owned}"],
    )
    result = analyze(parsed)
    codes = {e.code for e in result.evidence}
    assert "HOMOGLYPH_DOMAIN" not in codes  

def test_display_name_mismatch_flags_impersonation() -> None:
    hints = COMPANY_CONFIG.get("company_name_hints", [])
    if not hints:
        pytest.skip("company_name_hints nu e configurat - vezi D4")
    hint = hints[0]

    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_display_name=f"{hint.title()} Suport",
        from_address="suport@atacator-fals.ru",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.MALICIOUS
    codes = {e.code for e in result.evidence}
    assert "DISPLAY_NAME_MISMATCH" in codes 

def test_urgency_language_detected_as_low_evidence_only() -> None:
    """Urgenta artificiala e semnal coroborant, nu decide singura verdictul"""
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="cineva@exemplu-necunoscut.com",
        body_text="Actiune necesara: contul dvs va fi suspendat in 24 de ore.",
        html_extracted_text="Actiune necesara: contul dvs va fi suspendat in 24 de ore.",
    )
    result = analyze(parsed)
    codes = {e.code for e in result.evidence}
    assert "URGENCY_LANGUAGE" in codes
    # nu decide singur verdictul - fara alt semnal, ramane NEEDS_REVIEW, nu MALICIOUS
    assert result.verdict != Verdict.MALICIOUS


def test_credential_request_language_detected() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="cineva@exemplu-necunoscut.com",
        body_text="Va rugam sa confirmati datele de cont si sa introduceti parola.",
        html_extracted_text="Va rugam sa confirmati datele de cont si sa introduceti parola.",
    )
    result = analyze(parsed)
    codes = {e.code for e in result.evidence}
    assert "CREDENTIAL_REQUEST_LANGUAGE" in codes


def test_no_content_signals_on_clean_text() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="cineva@exemplu.ro",
        body_text="Buna ziua, atasez raportul de vanzari pentru luna aceasta.",
    )
    result = analyze(parsed)
    codes = {e.code for e in result.evidence}
    assert "URGENCY_LANGUAGE" not in codes
    assert "CREDENTIAL_REQUEST_LANGUAGE" not in codes    