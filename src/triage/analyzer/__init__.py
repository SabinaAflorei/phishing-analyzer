"""Verdictul e determinist. Fara AI aici. Fiecare semnal produce o dovada."""

from __future__ import annotations

import email.utils
from pathlib import Path
from typing import Any
import yaml

from triage.defang import defang
from triage.domains import is_subdomain_of
from triage.parser import ParsedEmail, ReportKind
from triage.verdicts import Analysis, Evidence, Severity, Verdict


def _find_config_dir() -> Path:
    """Caută directorul 'config' urcând în ierarhia de directoare."""
    current = Path(__file__).resolve().parent
    for _ in range(5):
        candidate = current / "config"
        if candidate.exists() and candidate.is_dir():
            return candidate
        current = current.parent
    return Path(__file__).resolve().parent.parent.parent.parent / "config"


CONFIG_DIR = _find_config_dir()


def load_yaml_config(file_name: str) -> dict[str, Any]:
    """Încarcă un fișier de configurație YAML din directorul config."""
    config_path = CONFIG_DIR / file_name
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


# Incarcare configuratii din YAML
CYBEREADY_CONFIG = load_yaml_config("cyberready.yaml")
ATTACHMENT_CONFIG = load_yaml_config("attachment_rules.yaml")

CYBEREADY_LEGACY_DOMAINS = {
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

# Combinare domenii din YAML cu cele legacy
config_domains = set(CYBEREADY_CONFIG.get("sender_domains", []))
ALL_CYBEREADY_DOMAINS = config_domains.union(CYBEREADY_LEGACY_DOMAINS)

CYBEREADY_IPS = set(CYBEREADY_CONFIG.get("sender_ips", []))
CYBEREADY_MSG_ID_SUFFIXES = set(CYBEREADY_CONFIG.get("message_id_suffixes", []))
CYBEREADY_HEADER_MARKERS = CYBEREADY_CONFIG.get("header_markers", {})

# Extensii de atasamente suspecte din attachment_rules.yaml
SUSPECT_EXTENSIONS = (
    set(ATTACHMENT_CONFIG.get("executable_extensions", []))
    | set(ATTACHMENT_CONFIG.get("script_extensions", []))
    | set(ATTACHMENT_CONFIG.get("macro_extensions", []))
    | {".exe", ".scr", ".vbs", ".bat", ".cmd", ".iso", ".img", ".ps1", ".docm", ".xlsm", ".pptm", ".com", ".pif", ".js", ".jse", ".wsf", ".hta", ".lnk", ".msi"
    }
)
DOUBLE_EXT_PATTERNS = ATTACHMENT_CONFIG.get("double_extension_patterns", []) or [
    ".pdf.exe",
    ".doc.exe",
    ".xls.exe",
    ".pdf.vbs",
]


def extract_email_address(raw_from: str) -> str:
    """Extrage curat adresa folosind email.utils.parseaddr."""
    if not raw_from:
        return ""
    _, addr = email.utils.parseaddr(raw_from)
    return addr.strip().lower() if addr else raw_from.strip().lower()


def is_cybeready_simulation(parsed: ParsedEmail) -> bool:
    """Verifică dacă e-mailul este o simulare CyberReady validă."""
    from_addr = extract_email_address(parsed.from_address)
    if not from_addr or "@" not in from_addr:
        return False

    domain = from_addr.split("@")[-1].lower()

    auth_lower = parsed.auth_results.lower() if parsed.auth_results else ""
    spf_fail = "spf=fail" in auth_lower or "dkim=fail" in auth_lower or "dmarc=fail" in auth_lower

    if spf_fail:
        return False

    if domain == "ses.distributie-energie.ro":
        suffixes = CYBEREADY_CONFIG.get("message_id_suffixes", ["@mta1.cybereadysmtp.com"])
        ips = CYBEREADY_CONFIG.get("sender_ips", [])
        return any(suf.lower() in auth_lower for suf in suffixes) or any(
            ip in auth_lower for ip in ips
        )

    return domain in ALL_CYBEREADY_DOMAINS or any(
        is_subdomain_of(domain, cb_dom) for cb_dom in ALL_CYBEREADY_DOMAINS
    )


def analyze(parsed: ParsedEmail) -> Analysis:
    evidence_list: list[Evidence] = []

    # 1. Verificare esec Autentificare (SPF/DKIM/DMARC Fail) -> MALICIOUS
    auth_lower = parsed.auth_results.lower() if parsed.auth_results else ""
    if "spf=fail" in auth_lower or "dkim=fail" in auth_lower or "dmarc=fail" in auth_lower:
        evidence_list.append(
            Evidence(
                code="AUTH_FAILURE",
                severity=Severity.HIGH,
                description="Verificarea autenticității e-mailului a eșuat (SPF/DKIM/DMARC).",
                detail=defang(parsed.auth_results),
            )
        )
        return Analysis(verdict=Verdict.MALICIOUS, confidence=0.9, evidence=evidence_list)

    # 2. Verificare SIMULATION (CyberReady Fingerprint)
    if is_cybeready_simulation(parsed):
        from_addr = extract_email_address(parsed.from_address)
        evidence_list.append(
            Evidence(
                code="CYBEREADY_SIMULATION",
                severity=Severity.INFO,
                description="E-mailul este o simulare autorizată CyberReady.",
                detail=defang(f"Expeditor: {from_addr}"),
            )
        )
        return Analysis(verdict=Verdict.SIMULATION, confidence=1.0, evidence=evidence_list)

    # 3. Verificare atasamente periculoase (Extensii suspecte, dubla extensie, macro-uri)
    for att in parsed.attachments:
        filename = att.filename.lower()
        ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
        has_double_ext = any(filename.endswith(pat) for pat in DOUBLE_EXT_PATTERNS)

        if ext in SUSPECT_EXTENSIONS or has_double_ext:
            evidence_list.append(
                Evidence(
                    code="SUSPECT_ATTACHMENT",
                    severity=Severity.CRITICAL,
                    description=f"Atașament cu risc securitate ridicat: {att.filename}",
                    detail=defang(f"SHA256: {att.sha256}"),
                )
            )
            return Analysis(verdict=Verdict.MALICIOUS, confidence=0.95, evidence=evidence_list)

    # 4. Verificare SCREENSHOT_ONLY
    if parsed.report_kind == ReportKind.SCREENSHOT_ONLY:
        evidence_list.append(
            Evidence(
                code="SCREENSHOT_ONLY",
                severity=Severity.MEDIUM,
                description="Raportul conține o captură de ecran și necesită revizuire manuală.",
            )
        )
        return Analysis(verdict=Verdict.NEEDS_REVIEW, confidence=0.5, evidence=evidence_list)

    # 5. Verificare stricta LEGITIMATE (SPF + DKIM + DMARC pass)
    if "spf=pass" in auth_lower and "dkim=pass" in auth_lower and "dmarc=pass" in auth_lower:
        evidence_list.append(
            Evidence(
                code="PASS_ALL_CHECKS",
                severity=Severity.INFO,
                description="Nicio amenințare detectată, autentificarea a trecut cu succes.",
            )
        )
        return Analysis(verdict=Verdict.LEGITIMATE, confidence=0.85, evidence=evidence_list)

    # 6. Fallback Implicit -> NEEDS_REVIEW
    evidence_list.append(
        Evidence(
            code="INSUFFICIENT_EVIDENCE",
            severity=Severity.MEDIUM,
            description="E-mailul nu conține suficiente semnale clare și necesită analiză manuală.",
        )
    )
    return Analysis(verdict=Verdict.NEEDS_REVIEW, confidence=0.5, evidence=evidence_list)