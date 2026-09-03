"""Verdictul e determinist. Fara AI aici. Fiecare semnal produce o dovada."""

from __future__ import annotations

import email.utils
from pathlib import Path
from typing import Any
import yaml
import re as _re
from triage.defang import defang
from triage.domains import is_subdomain_of
from triage.parser import ParsedEmail, ReportKind
from triage.verdicts import Analysis, Evidence, Severity, Verdict
from urllib.parse import urlparse


def _find_config_dir() -> Path:
    """Caută directorul 'config' urcând în ierarhia de directoare."""
    current = Path(__file__).resolve().parent
    for _ in range(5):
        candidate = current / "config"
        if candidate.exists() and candidate.is_dir():
            return candidate
        current = current.parent
    return Path(__file__).resolve().parent.parent.parent.parent / "config"

# TODO(curatenie): PROJECT_ROOT nu e folosit nicaieri si oricum indica spre
# src/, nu spre radacina proiectului (parents[0]=analyzer, [1]=triage, [2]=src).
# Sterge-l.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = _find_config_dir()


def load_yaml_config(file_name: str) -> dict[str, Any]:
    """Încarcă un fișier de configurație YAML din directorul config."""
    config_path = CONFIG_DIR / file_name
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as f:
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

# TODO(curatenie): cele trei constante de mai jos sunt calculate dar nefolosite -
# is_cybeready_simulation reciteste CYBEREADY_CONFIG pe loc. Alege o varianta:
# ori le folosesti aici, ori le stergi. CYBEREADY_HEADER_MARKERS (X-CRPS,
# X-Virtual-MTA) nu e citit de nicaieri, desi comentariul "Semnal 4" din
# is_cybeready_simulation pretinde ca ar fi. Ori implementezi semnalul, ori
# scoti comentariul.
CYBEREADY_IPS = set(CYBEREADY_CONFIG.get("sender_ips", []))
CYBEREADY_MSG_ID_SUFFIXES = set(CYBEREADY_CONFIG.get("message_id_suffixes", []))
CYBEREADY_HEADER_MARKERS = CYBEREADY_CONFIG.get("header_markers", {})

# Extensii de atasamente suspecte din attachment_rules.yaml
#
# TODO(bug): ".iso" si ".img" nu mai sunt semnalate deloc - e o regresie fata de
# commit-ul dinainte de 4bb6467, unde erau in lista hardcodata.
# Ce e gresit: se citesc doar "executable_extensions", "script_extensions" (cheie
# care nici nu exista in attachment_rules.yaml) si "macro_enabled_extensions".
# Cheia "archive_extensions", unde stau iso, img, zip, rar, 7z, nu e citita.
# Verificat: ".exe" -> True, ".docm" -> True, dar ".iso" -> False, ".img" -> False.
# Fisierele ISO sunt un mod foarte folosit de livrare de malware, tocmai pentru ca
# trec de filtrele care se uita doar la .exe.
# Cum rezolvi: adauga "archive_extensions" in reuniune si scoate
# "script_extensions" care nu exista.
# Pont general: .get(cheie, []) pe o cheie scrisa gresit nu da niciodata eroare,
# doar tacere. Merita o verificare la pornire care sa strige daca lipseste o cheie
# asteptata din config.
raw_extensions = (
    set(ATTACHMENT_CONFIG.get("executable_extensions", []))
    | set(ATTACHMENT_CONFIG.get("script_extensions", []))
    | set(ATTACHMENT_CONFIG.get("macro_enabled_extensions", []))
)

# Adaugare ".exe" și "exe" pentru a preveni bug-urile de parsare
SUSPECT_EXTENSIONS = set()
for ext in raw_extensions:
    ext_clean = ext.lower().strip()
    SUSPECT_EXTENSIONS.add(ext_clean)
    if ext_clean.startswith("."):
        SUSPECT_EXTENSIONS.add(ext_clean[1:])  # varianta fara punct
    else:
        SUSPECT_EXTENSIONS.add(f".{ext_clean}")  #varianta cu punct

# TODO(bug): regex-ul de dubla extensie condamna fisiere perfect normale.
# Ce e bine: ai trecut de la lista hardcodata la regex-ul din config, corect.
# Ce e gresit: regex-ul nu pune nicio conditie pe a DOUA extensie -
#   \.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.[a-z0-9]{2,4}$
# Testat pe codul asta:
#   invoice.pdf.exe   -> MALICIOUS 0.95  (corect)
#   raport.xls.pdf    -> MALICIOUS 0.95  (fals pozitiv)
#   poza.jpg.png      -> MALICIOUS 0.95  (fals pozitiv)
#   contract.doc.docx -> MALICIOUS 0.95  (fals pozitiv)
# Cum rezolvi: periculoasa e combinatia "pare document, dar e executabil", deci a
# doua extensie trebuie sa fie una din SUSPECT_EXTENSIONS. Cel mai simplu: lasa
# regex-ul sa prinda tiparul de dubla extensie, iar dupa ce a prins verifica in
# cod, la punctul 3 din analyze(), ca extensia finala chiar e in SUSPECT_EXTENSIONS.
_double_ext_pattern_str = ATTACHMENT_CONFIG.get("suspicious_double_extension_pattern")
_DOUBLE_EXT_REGEX = _re.compile(_double_ext_pattern_str, _re.IGNORECASE) if _double_ext_pattern_str else None


def extract_email_address(raw_from: str) -> str:
    """Extrage curat adresa folosind email.utils.parseaddr."""
    if not raw_from:
        return ""
    _, addr = email.utils.parseaddr(raw_from)
    return addr.strip().lower() if addr else raw_from.strip().lower()


def is_cybeready_simulation(parsed: ParsedEmail) -> bool:
    from_addr = extract_email_address(parsed.from_address)
    domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    auth_lower = (parsed.auth_results or "").lower()
    if "spf=fail" in auth_lower or "dkim=fail" in auth_lower or "dmarc=fail" in auth_lower:
        return False

    is_cyberready_domain = bool(domain) and (
        domain in ALL_CYBEREADY_DOMAINS
        or any(is_subdomain_of(domain, cb) for cb in ALL_CYBEREADY_DOMAINS)
    )

    # Semnal 1: suffix de Message-ID in Message-ID / In-Reply-To / References
    suffixes = [s.lower() for s in CYBEREADY_CONFIG.get("message_id_suffixes", [])]
    msgid_fields = " ".join([
        parsed.message_id or "", parsed.in_reply_to or "", parsed.references or ""
    ]).lower()
    has_msgid_signal = any(suf in msgid_fields for suf in suffixes if suf)

    # Semnal 1b: acelasi suffix poate aparea si in Authentication-Results,ca identitate DKIM (header.i=@mta1.cybereadysmtp.com)
    has_auth_suffix_signal = any(suf in auth_lower for suf in suffixes if suf)

    # Semnal 2: IP cunoscut in lantul de Received
    ips = set(CYBEREADY_CONFIG.get("sender_ips", []))
    received_text = " ".join(parsed.received_chain).lower()
    has_ip_signal = any(ip in received_text for ip in ips) or any(ip in auth_lower for ip in ips)

    # Semnal 3: hostname de tracking in URL-uri (domeniu inregistrabil, nu substring!)
    tracking_hosts = {h.lower() for h in CYBEREADY_CONFIG.get("tracking_hostnames", [])}
    url_hosts = {urlparse(u).netloc.lower() for u in parsed.urls if u}
    has_tracking_signal = any(
        h == th or is_subdomain_of(h, th)
        for h in url_hosts for th in tracking_hosts
    )
    # TODO(securitate, prioritate mare): un hostname de tracking singur da
    # SIMULATION oricui. Vezi si return-ul de la finalul functiei.
    # Ce e gresit: toate cele patru semnale intra in acelasi SAU, deci sunt
    # tratate ca fiind la fel de puternice. Nu sunt. Un Message-ID sau un IP din
    # Received sunt greu de falsificat; un URL in corpul mailului il pune oricine.
    # Testat: attacker@totally-evil.tld cu un link catre https://inner.website/...
    #   -> SIMULATION 1.0
    # De ce e grav: inner.website e un domeniu generic, scris in
    # config/cyberready.yaml, care e public in repo. Cine citeste repo-ul poate
    # sa puna link-ul ala in phishing si sa primeasca automat raspunsul bland de
    # "a fost doar o simulare". Comentariul din capul lui cyberready.yaml spune
    # exact asta: un fals pozitiv aici e inacceptabil.
    # Cum rezolvi: semnalul de tracking trebuie sa CONFIRME un expeditor deja
    # plauzibil, nu sa decida singur. Cere fie domeniu CyberReady plus un semnal,
    # fie doua semnale independente. Separa semnalele tari (msgid, ip) de cele
    # slabe (url) in doua variabile, nu le lasa pe toate in acelasi SAU.
    has_extra_signal = (
        has_msgid_signal or has_auth_suffix_signal or has_ip_signal or has_tracking_signal
    )
    # Semnal 4: header propriu al platformei (X-CRPS, X-Virtual-MTA) 
    if is_cyberready_domain:
        yaml_domains = {str(d).lower().strip() for d in CYBEREADY_CONFIG.get("sender_domains", [])}
        is_sensitive = domain in yaml_domains or any(
            is_subdomain_of(domain, sd) for sd in yaml_domains
        )
        if is_sensitive:
            return has_extra_signal
        return True

    # Fara domeniu confirmat (cazul 01 - forward inline, From e al colegului):
    # cel putin un semnal independent de domeniu.
    #
    # BINE: partea asta chiar functioneaza. Testat, forward inline cu
    # In-Reply-To: <...@mta1.cybereadysmtp.com> -> SIMULATION 1.0. Era partea grea.
    #
    # TODO(securitate): aici cade bug-ul cu tracking-ul de mai sus. Cand ajungi
    # pe linia asta, un simplu link catre inner.website e suficient.
    return has_extra_signal


# TODO(prioritate maxima): fisierul asta nu exista, deci toate seturile de mai jos
# sunt goale, si odata cu ele o gramada de reguli devin cod mort.
# Ce e gresit: config/company_domains.yaml e in .gitignore (corect, contine nume
# de servere interne). In repo exista doar company_domains.example.yaml. Pe orice
# clona noua si in CI, verificat:
#   TRUSTED_PARTNERS = set()   COMPANY_OWNED  = set()
#   MAIL_INFRA       = set()   HIGH_RISK_TLDS = set()
# Adica regula de newsletter legitim (cazul 06), INTERNAL_DOMAIN_SPOOF,
# LOOKALIKE_DOMAIN si HIGH_RISK_TLD nu se executa NICIODATA in CI. Tot ce s-a
# scris in commit-ul e53d727 e cod mort acolo, si bug-urile marcate mai jos in
# _check_domain_spoofing nu pot fi prinse de niciun test cat timp seturile sunt goale.
# Cum rezolvi: in load_yaml_config, daca fisierul cerut nu exista, incearca
# varianta .example cu acelasi nume si scrie un logger.warning ca s-a folosit
# exemplul. Asa CI are date de lucru, iar pe VM fisierul real are prioritate.
# Datele reale raman in afara git-ului.
# FA PUNCTUL ASTA PRIMUL - transforma bug-urile din _check_domain_spoofing din
# teoretice in testabile.
COMPANY_CONFIG = load_yaml_config("company_domains.yaml")
TRUSTED_PARTNERS = {d.lower().strip() for d in COMPANY_CONFIG.get("trusted_partners", [])}

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

    # 3. Verificare atasamente periculoase
    for att in parsed.attachments:
        filename = att.filename.lower()
        has_double_ext = bool(_DOUBLE_EXT_REGEX and _DOUBLE_EXT_REGEX.search(filename))
        ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""

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

    body_content = parsed.body_text or ""
    subject_text = parsed.subject or ""
    from_addr = extract_email_address(parsed.from_address)
    sender_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    #  spoofing / lookalike de domeniu propriu ---
    # TODO(bug): aici orice evidenta intoarsa de _check_domain_spoofing devine
    # MALICIOUS 0.9, indiferent de severitatea ei. Dar 5c construieste evidenta cu
    # Severity.MEDIUM, deci un expeditor pe .online, fara niciun alt semnal, e
    # condamnat doar pentru TLD. Testat: news@furnizor.online -> MALICIOUS 0.9.
    # In plus blocul asta ruleaza INAINTE de regula 6 (partener de incredere) si
    # inainte de 7 (SPAM), deci le taie pe amandoua.
    # Cum rezolvi: TLD-ul e un indiciu slab, nu o dovada. Ori adaugi evidenta in
    # evidence_list fara return si lasi fluxul sa continue, ori mapezi severitatea
    # la verdict (CRITICAL/HIGH -> MALICIOUS, MEDIUM -> NEEDS_REVIEW).
    # Regula de urmat peste tot in analizor: severitatea evidentei si verdictul
    # trebuie sa fie corelate. Daca scrii Severity.MEDIUM, nu intoarce MALICIOUS 0.9.
    spoof_evidence = _check_domain_spoofing(parsed, sender_domain)
    if spoof_evidence:
        evidence_list.append(spoof_evidence)
        return Analysis(verdict=Verdict.MALICIOUS, confidence=0.9, evidence=evidence_list)

    # 5. Verificare Prompt Injection
    # TODO(bug de logica): regula asta face exact invers decat cere cazul 08.
    # corpus/expected/08_prompt_injection.yaml spune: "verdictul produs cu si fara
    # textul ascuns trebuie sa fie identic". Ideea cerintei e ca textul ascuns sa
    # NU poata influenta verdictul, in nicio directie. Regula de aici face din
    # caracterele ascunse chiar MOTIVUL verdictului MALICIOUS - adica textul ascuns
    # schimba verdictul, fix ce nu voia cerinta.
    # Cazul 08 trebuie sa iasa MALICIOUS din semnalele de phishing de credentiale
    # (link, domeniu, autentificare), iar injectia doar sa fie curatata inainte sa
    # ajunga la model.
    # Efect masurat: un newsletter legitim Microsoft cu UN SINGUR caracter
    # zero-width in corp iese MALICIOUS 0.9 [PROMPT_INJECTION]. Caracterele
    # zero-width si preheader-ele display:none sunt banale in mailurile de
    # marketing, deci o sa ai o gramada de falsi pozitivi.
    # A doua problema: textul ascuns nici macar nu ajunge aici. Vezi TODO-ul de la
    # ramura text/html din parser (cauta "if not body_text_parts"). Testat pe un
    # mail de forma cazului 08: textul de injectie nu a ajuns in body_text, iar
    # verdictul a iesit NEEDS_REVIEW 0.5.
    # Cum rezolvi: ai deja sanitize_for_model in triage/drafter/__init__.py, aia e
    # unealta corecta si e deja folosita la construirea prompt-ului. Scoate regula
    # asta ca sursa de verdict; daca vrei sa pastrezi urma, adauga evidenta
    # informativa in evidence_list fara return.
    if any(char in body_content for char in ["\u200b", "\u200c", "\u200d", "\u202e"]) or "display:none" in body_content.lower():
        evidence_list.append(
            Evidence(
                code="PROMPT_INJECTION",
                severity=Severity.HIGH,
                description="Tentativă de prompt injection detectată prin caractere ascunse sau stiluri de afișare.",
                detail=defang("Detectat conținut ascuns sau override de direcție în corpul e-mailului.")
            )
        )
        return Analysis(verdict=Verdict.MALICIOUS, confidence=0.9, evidence=evidence_list)

    # 6. Verificare Newsletter / Partener de încredere
    is_trusted_partner = sender_domain in TRUSTED_PARTNERS or any(
        is_subdomain_of(sender_domain, tp) for tp in TRUSTED_PARTNERS
    )

    has_no_explicit_fail = (
        "spf=fail" not in auth_lower
        and "dkim=fail" not in auth_lower
        and "dmarc=fail" not in auth_lower
    )
    has_partner_newsletter_markers = "newsletter" in subject_text.lower() or "informare" in subject_text.lower()

    if is_trusted_partner and has_no_explicit_fail and has_partner_newsletter_markers:
        evidence_list.append(
            Evidence(
                code="LEGIT_NEWSLETTER",
                severity=Severity.LOW,
                description="Newsletter legitim de la un partener de încredere (furnizor cunoscut).",
                detail=defang(f"Expeditor: {from_addr}, Subiect: {subject_text}"),
            )
        )
        return Analysis(verdict=Verdict.LEGITIMATE, confidence=0.85, evidence=evidence_list)

    # 7. Verificare SPAM
    is_spam_report = parsed.report_kind == ReportKind.SPAM
    has_marketing_keywords = (
        "publicitate" in body_content.lower()
        or "eveniment" in body_content.lower()
        or "conferință" in body_content.lower()
        or "conferinta" in body_content.lower()
        or "invitație" in body_content.lower()
        or "invitatie" in body_content.lower()
        or "simpozion" in body_content.lower()
    )
    has_unsubscribe = "dezabonare" in body_content.lower() or "unsubscribe" in body_content.lower()

    if is_spam_report or has_marketing_keywords or (has_unsubscribe and not is_trusted_partner):
        evidence_list.append(
            Evidence(
                code="REPORTED_AS_SPAM",
                severity=Severity.LOW,
                description="Mesajul este raportat ca fiind spam sau conține oferte promoționale/evenimente nesolicitate.",
                detail=defang("Detectate elemente de marketing/spam fără risc direct de malware.")
            )
        )
        return Analysis(verdict=Verdict.SPAM, confidence=0.85, evidence=evidence_list)

    # 8. Verificare stricta LEGITIMATE
    if "spf=pass" in auth_lower and "dkim=pass" in auth_lower and "dmarc=pass" in auth_lower:
        evidence_list.append(
            Evidence(
                code="PASS_ALL_CHECKS",
                severity=Severity.INFO,
                description="Nicio amenințare detectată, autentificarea a trecut cu succes.",
            )
        )
        return Analysis(verdict=Verdict.LEGITIMATE, confidence=0.85, evidence=evidence_list)

    # 9. Fallback Implicit -> NEEDS_REVIEW
    evidence_list.append(
        Evidence(
            code="INSUFFICIENT_EVIDENCE",
            severity=Severity.MEDIUM,
            description="E-mailul nu conține suficiente semnale clare și necesită analiză manuală.",
        )
    )
    return Analysis(verdict=Verdict.NEEDS_REVIEW, confidence=0.5, evidence=evidence_list)


# TODO: cele trei seturi sunt GOALE pe orice clona noua si in CI, pentru ca
# company_domains.yaml nu exista in repo. Vezi TODO-ul mare de la
# "COMPANY_CONFIG = load_yaml_config(...)". Cat timp sunt goale, toata functia
# _check_domain_spoofing de mai jos e cod mort si nu o poate testa nimeni.
COMPANY_OWNED = {d.lower().strip() for d in COMPANY_CONFIG.get("owned_domains", [])}
MAIL_INFRA = {h.lower().strip() for h in COMPANY_CONFIG.get("mail_infrastructure", [])}
HIGH_RISK_TLDS = {t.lower().strip() for t in COMPANY_CONFIG.get("high_risk_tlds", [])}

def _check_domain_spoofing(parsed: ParsedEmail, sender_domain: str) -> Evidence | None:
    # 5a. From pretinde un domeniu propriu, dar Received nu trece prin infra proprie
    claims_owned = sender_domain in COMPANY_OWNED or any(
        is_subdomain_of(sender_domain, d) for d in COMPANY_OWNED
    )
    if claims_owned:
        received_text = " ".join(parsed.received_chain).lower()
        routed_internally = any(h in received_text for h in MAIL_INFRA)
        if not routed_internally:
            return Evidence(
                code="INTERNAL_DOMAIN_SPOOF",
                severity=Severity.CRITICAL,
                description="Expeditorul pretinde un domeniu propriu, dar mesajul nu a trecut prin infrastructura de mail internă.",
                detail=defang(f"Domeniu: {sender_domain}"),
            )

    # 5b. Lookalike fata de domeniile proprii (Levenshtein simplu)
    # TODO(bug, prioritate maxima): bucla asta marcheaza domeniile NOASTRE ca
    # MALICIOUS. E cel mai grav fals pozitiv din tot analizorul.
    # Ce e gresit: se sare peste comparatie doar daca domeniile sunt identice
    # (sender_domain != owned). Dar domeniile proprii seamana intre ele. Cu lista
    # din config (exemplu.ro, intern.exemplu.ro, exemplu.com), distanta
    # Levenshtein intre "exemplu.com" si "exemplu.ro" este 2, deci trece pragul <= 2.
    # Testat:
    #   From ceo@exemplu.com (domeniu propriu, prin mx01.exemplu.com)  -> MALICIOUS 0.9
    #   From hr@exemplu.ro   (domeniu propriu, prin mail1.exemplu.ro)  -> MALICIOUS 0.9
    # Adica orice mail intern devine malitios.
    # Cum rezolvi: lookalike are sens doar pentru domenii care NU sunt ale noastre.
    # Ai deja claims_owned calculat mai sus in aceeasi functie - pune toata bucla
    # sub "if not claims_owned:". Daca expeditorul e chiar pe un domeniu propriu,
    # nu are cum sa fie un lookalike al domeniului propriu.
    for owned in COMPANY_OWNED:
        if sender_domain != owned and _levenshtein(sender_domain, owned) <= 2:
            return Evidence(
                code="LOOKALIKE_DOMAIN",
                severity=Severity.HIGH,
                description=f"Domeniul expeditorului seamănă cu un domeniu propriu ({owned}), dar nu este identic.",
                detail=defang(f"Domeniu raportat: {sender_domain}"),
            )

    # 5c. TLD cu risc ridicat
    # TODO(bug): evidenta asta e MEDIUM, dar apelantul din analyze() o transforma
    # in MALICIOUS 0.9. Vezi TODO-ul de la "spoof_evidence = _check_domain_spoofing".
    # Un TLD e un indiciu slab, nu o dovada - nu poti condamna un expeditor doar
    # pentru ca e pe .online.
    tld = "." + sender_domain.rsplit(".", 1)[-1] if "." in sender_domain else ""
    if tld in HIGH_RISK_TLDS:
        return Evidence(
            code="HIGH_RISK_TLD",
            severity=Severity.MEDIUM,
            description=f"Domeniul expeditorului folosește un TLD cu risc ridicat ({tld}).",
        )

    return None


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]
