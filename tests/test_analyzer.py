from __future__ import annotations

from triage.analyzer import analyze
from triage.parser import ParsedAttachment, ParsedEmail, ReportKind
from triage.verdicts import Verdict


def test_analyze_cyberready_simulation() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="test@cyberreadysmtp.com",
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

def test_analyze_legitimate() -> None:
    parsed = ParsedEmail(
        report_kind=ReportKind.UNKNOWN,
        from_address="user@company.com",
        auth_results="spf=pass dkim=pass",
    )
    result = analyze(parsed)
    assert result.verdict == Verdict.LEGITIMATE