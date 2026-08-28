"""Verdictul e determinist. Fara AI aici. Fiecare semnal produce o dovada."""

from __future__ import annotations

from triage.domains import registered_domain
from triage.parser import ParsedEmail, ReportKind
from triage.verdicts import Analysis, Evidence, Severity, Verdict

CYBEREADY_DOMAINS: set[str] = {
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
}

SUSPECT_EXTENSIONS = {".exe", ".scr", ".vbs", ".bat", ".cmd", ".iso", ".img", ".ps1"}


def is_cybeready_domain(email_address: str) -> bool:
    """Verifică dacă domeniul sau domeniul înregistrat se află în lista CyberReady."""
    if not email_address or "@" not in email_address:
        return False

    raw_domain = email_address.split("@")[-1].rstrip(">").strip().lower()
    reg_domain = registered_domain(raw_domain)

    return raw_domain in CYBEREADY_DOMAINS or reg_domain in CYBEREADY_DOMAINS


def analyze(parsed: ParsedEmail) -> Analysis:
    evidence_list: list[Evidence] = []

    sender_addr = getattr(parsed, "from_address", "") or ""

    # 1. Verificare SIMULATION (CyberReady Fingerprint)
    if is_cybeready_domain(sender_addr):
        evidence_list.append(
            Evidence(
                code="CYBERREADY_SIMULATION",
                severity=Severity.INFO,
                description="E-mailul este o simulare autorizată CyberReady.",
                detail=f"Expeditor: {sender_addr}",
            )
        )
        return Analysis(verdict=Verdict.SIMULATION, confidence=1.0, evidence=evidence_list)

    # 2. Verificare SCREENSHOT_ONLY
    if parsed.report_kind == ReportKind.SCREENSHOT_ONLY:
        evidence_list.append(
            Evidence(
                code="SCREENSHOT_ONLY",
                severity=Severity.MEDIUM,
                description="Raportul conține o captură de ecran și necesită revizuire manuală.",
            )
        )
        return Analysis(verdict=Verdict.NEEDS_REVIEW, confidence=0.5, evidence=evidence_list)

    # 3. Verificare Autentificare (SPF / DKIM / DMARC)
    auth_lower = parsed.auth_results.lower() if parsed.auth_results else ""
    if "spf=fail" in auth_lower or "dkim=fail" in auth_lower or "dmarc=fail" in auth_lower:
        evidence_list.append(
            Evidence(
                code="AUTH_FAILURE",
                severity=Severity.HIGH,
                description="Verificarea autenticității e-mailului a eșuat (SPF/DKIM/DMARC).",
                detail=parsed.auth_results,
            )
        )
        return Analysis(verdict=Verdict.MALICIOUS, confidence=0.9, evidence=evidence_list)

    # 4. Verificare Atașamente Periculoase
    for att in parsed.attachments:
        ext = "." + att.filename.rsplit(".", 1)[-1].lower() if "." in att.filename else ""
        if ext in SUSPECT_EXTENSIONS:
            evidence_list.append(
                Evidence(
                    code="SUSPECT_ATTACHMENT",
                    severity=Severity.CRITICAL,
                    description=f"Atașament cu extensie potențial periculoasă: {att.filename}",
                    detail=f"SHA256: {att.sha256}",
                )
            )
            return Analysis(verdict=Verdict.MALICIOUS, confidence=0.95, evidence=evidence_list)

    # 5. Implicit: E-mail Legitim
    evidence_list.append(
        Evidence(
            code="PASS_ALL_CHECKS",
            severity=Severity.INFO,
            description="Nicio amenințare sau anomalie detectată.",
        )
    )
    return Analysis(verdict=Verdict.LEGITIMATE, confidence=0.85, evidence=evidence_list)