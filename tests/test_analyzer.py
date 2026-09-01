from __future__ import annotations

import pytest
from triage.analyzer import analyze
from triage.parser import ParsedAttachment, ParsedEmail, ReportKind
from triage.verdicts import Verdict


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
    assert result.confidence == 0.9


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
    assert result.confidence == 0.9


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
    assert result.confidence == 0.95


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