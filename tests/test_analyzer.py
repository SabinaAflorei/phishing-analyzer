from __future__ import annotations

import pytest
from triage.analyzer import analyze
from triage.parser import ParsedAttachment, ParsedEmail, ReportKind
from triage.verdicts import Verdict


def test_analyze_cyberready_simulation() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="test@admin-support.site",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.SIMULATION
    assert result.confidence == 1.0


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


# TODO: testul fixeaza bug-ul in loc sa il prinda. Are doar spf=pass si dkim=pass,
# fara DMARC si cu domeniu necunoscut, si totusi cere LEGITIMATE. 5 cere toate
# trei plus domeniu cunoscut.
def test_analyze_legitimate() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="user@company.com",
        auth_results="spf=pass dkim=pass",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.LEGITIMATE


@pytest.mark.parametrize(
    "cybeready_domain",
    [
        "act-now-www.org",
        "admin-support.site",
        "cloud-mail.store",
        "ses.distributie-energie.ro",
    ],
)
def test_cybeready_simulation_domains(cybeready_domain: str) -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address=f"simulation-test@{cybeready_domain}",
    )
    analysis = analyze(parsed)

    assert analysis.verdict == Verdict.SIMULATION
    assert analysis.confidence == 1.0
    assert analysis.evidence[0].code == "CYBERREADY_SIMULATION"


# TODO: lipseste testul cel mai important pentru 8.1: From falsificat cu un domeniu
# de simulare dar cu SPF fail NU trebuie sa iasa SIMULATION.
# TODO: lipsesc teste pentru SPAM, pentru atasament cu macro (docm), pentru mail
# fara Authentication-Results si pentru dubla extensie.
