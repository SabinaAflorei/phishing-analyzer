"""Verdictul e determinist. Fara AI aici. Fiecare semnal produce o dovada."""

from __future__ import annotations

from triage.domains import registered_domain
from triage.parser import ParsedEmail, ReportKind
from triage.verdicts import Analysis, Evidence, Severity, Verdict

# TODO: 6.3 zice explicit ca fingerprint-ul sta in YAML, nu in cod. Exista deja
# config/cyberready.yaml si nu e citit de nimeni.
# TODO: lista de aici nu se potriveste cu yaml-ul. In yaml sunt notificaton.online,
# crsmtp.notificaton.online si cybereadysmtp.com; aici au aparut 9 domenii noi si
# au disparut doua. Doua surse de adevar care spun lucruri diferite.
# TODO: yaml-ul mai are sender_ips, tracking_hostnames, header_markers si
# message_id_suffixes - toate cerute de 6.3 si niciunul folosit. Cazul 01 din
# corpus se prinde tocmai pe message_id_suffixes, deci acum nu il prinde.
# TODO: ses.distributie-energie.ro e domeniu de firma reala. Daca a intrat aici
# gresit, orice mail real de la ei primeste SIMULATION - fix falsul pozitiv
# interzis de 8.1. Verifica de unde vine lista.
# TODO: numele e scris in trei feluri: CYBEREADY_DOMAINS, is_cybeready_domain si
# codul de dovada CYBERREADY_SIMULATION. Codul ajunge in DB si in post-mortem,
# deci alege o singura forma.
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

# TODO: exista config/attachment_rules.yaml si nu e citit. Acolo sunt deja
# listele complete.
# TODO: lipsesc docm, xlsm, pptm. Cazul 04 din corpus e exact atasament cu macro,
# deci acum iese LEGITIMATE in loc de MALICIOUS.
# TODO: lipsesc si com, pif, js, jse, wsf, hta, lnk, msi din yaml.
# TODO: nu se verifica dubla extensie (yaml are pattern-ul) si nici arhivele
# protejate cu parola, desi 6.3 le cere pe amandoua.
SUSPECT_EXTENSIONS = {".exe", ".scr", ".vbs", ".bat", ".cmd", ".iso", ".img", ".ps1"}


# TODO: v1 folosea is_subdomain_of din domains.py. Acolo scrie de ce exista:
# ca 'notcybereadysmtp.com' sa nu treaca drept subdomeniu. v2 l-a scos.
def is_cybeready_domain(email_address: str) -> bool:
    """Verifică dacă domeniul sau domeniul înregistrat se află în lista CyberReady."""
    if not email_address or "@" not in email_address:
        return False

    # TODO: From e de forma 'Nume Prenume <user@domeniu.ro>'. Taierea manuala cu
    # split('@')[-1] se strica daca numele afisat contine un @. Foloseste
    # email.utils.parseaddr, e in stdlib.
    raw_domain = email_address.split("@")[-1].rstrip(">").strip().lower()
    reg_domain = registered_domain(raw_domain)

    return raw_domain in CYBEREADY_DOMAINS or reg_domain in CYBEREADY_DOMAINS


# TODO: SPAM nu se produce niciodata, nu exista nicio cale care sa il intoarca.
# Sunt 5 categorii in 5, iar cazul 07 din corpus e spam de marketing, deci
# criteriul 8.1 (toate cele 11 cazuri cu verdict corect) nu are cum sa treaca.
# TODO: din 6.3 lipsesc inca: From care pretinde domeniul companiei dar vine din
# afara, Reply-To diferit de From, Return-Path care nu corespunde, domenii
# lookalike (Levenshtein, homoglife, punycode), TLD-uri riscante, nepotrivire
# display-name / domeniu, si semnalele de continut. Parserul le extrage deja pe
# reply_to si return_path, dar nu le citeste nimeni.
# TODO: scorurile de incredere sunt constante scrise de mana, nu calculate din
# dovezi.
def analyze(parsed: ParsedEmail) -> Analysis:
    evidence_list: list[Evidence] = []

    # TODO: getattr cu valoare de rezerva nu e nevoie, ParsedEmail are campul cu
    # default. Asa ascunzi o greseala de scriere a numelui campului.
    sender_addr = getattr(parsed, "from_address", "") or ""

    # TODO: verdictul de simulare se ia doar dupa From, care se falsifica trivial.
    # Un atacator care pune From: x@admin-support.site primeste SIMULATION cu
    # incredere 1.0, iar colegul primeste raspunsul bland. 8.1 spune ca fals
    # pozitivele aici sunt inacceptabile. Coroboreaza cu SPF pass, IP-ul de
    # expediere sau hostname-ul de tracking din yaml.
    # TODO: fiecare regula face return imediat, deci restul dovezilor nu se mai
    # aduna. 6.3 cere ca verdictul sa fie functie de dovezi, iar semnalele de
    # continut sunt coroborante - nu au cum sa contribuie daca iesim la prima.
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

    # TODO: detail primeste auth_results brut, care contine IP-uri si domenii.
    # Dovada ajunge in DB si in dashboard, deci trece prin defang (4.2 si 8.2).
    # Acelasi lucru la dovada de simulare, unde detail are adresa expeditorului.
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

    # 4. Verificare Atasamente Periculoase
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

    # TODO: aici e cea mai grava. LEGITIMATE nu poate fi valoarea implicita.
    # 5 cere SPF + DKIM + DMARC pass SI domeniu cunoscut, iar la cea mai mica
    # indoiala se trece la NEEDS_REVIEW. Acum un mail fara Authentication-Results
    # (cazul 09, headere lipsa) cade direct pe LEGITIMATE cu incredere 0.85.
    # Implicitul trebuie sa fie NEEDS_REVIEW.
    # 5. Implicit: E-mail Legitim
    evidence_list.append(
        Evidence(
            code="PASS_ALL_CHECKS",
            severity=Severity.INFO,
            description="Nicio amenințare sau anomalie detectată.",
        )
    )
    return Analysis(verdict=Verdict.LEGITIMATE, confidence=0.85, evidence=evidence_list)