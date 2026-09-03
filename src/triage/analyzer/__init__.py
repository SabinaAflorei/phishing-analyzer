"""Verdictul e determinist. Fara AI aici. Fiecare semnal produce o dovada.

Structura, dupa sectiunea 6.3:

1. `_collect_evidence` ruleaza TOATE regulile si aduna dovezile. Nicio regula nu
   iese devreme, deci semnalele se coroboreaza in loc sa se anuleze intre ele.
2. `_decide` transforma dovezile in verdict, dupa un tabel de ponderi si doua
   praguri. "Verdictul e o functie de dovezi" - la propriu, o singura functie.

Regula pe care o respecta tot fisierul: severitatea unei dovezi si greutatea ei
in scor merg impreuna. Daca scrii Severity.MEDIUM, nu poti obtine MALICIOUS 0.9
dintr-un singur semnal.
"""

from __future__ import annotations

import email.utils
import re
from urllib.parse import urlparse

from confusable_homoglyphs import confusables

from triage.config import load_yaml_config, require_keys
from triage.defang import defang
from triage.domains import is_subdomain_of, registered_domain
from triage.parser import ParsedEmail, ReportKind
from triage.verdicts import Analysis, Evidence, Severity, Verdict

# ---------------------------------------------------------------------------
# Configurare
# ---------------------------------------------------------------------------

CYBEREADY_CONFIG = load_yaml_config("cyberready.yaml")
ATTACHMENT_CONFIG = load_yaml_config("attachment_rules.yaml")
COMPANY_CONFIG = load_yaml_config("company_domains.yaml")

require_keys(
    ATTACHMENT_CONFIG,
    ["executable_extensions", "macro_enabled_extensions", "archive_extensions"],
    "attachment_rules.yaml",
)
require_keys(
    CYBEREADY_CONFIG,
    ["sender_domains", "sender_ips", "tracking_hostnames", "header_markers"],
    "cyberready.yaml",
)
require_keys(
    COMPANY_CONFIG,
    ["owned_domains", "mail_infrastructure", "trusted_partners", "high_risk_tlds"],
    "company_domains.yaml",
)


def _lower_set(values: object) -> set[str]:
    if not isinstance(values, list):
        return set()
    return {str(v).strip().lower() for v in values if str(v).strip()}


CYBEREADY_DOMAINS = _lower_set(CYBEREADY_CONFIG.get("sender_domains"))
CYBEREADY_IPS = _lower_set(CYBEREADY_CONFIG.get("sender_ips"))
CYBEREADY_MSG_ID_SUFFIXES = _lower_set(CYBEREADY_CONFIG.get("message_id_suffixes"))
CYBEREADY_TRACKING_HOSTS = _lower_set(CYBEREADY_CONFIG.get("tracking_hostnames"))
CYBEREADY_HEADER_MARKERS = _lower_set(CYBEREADY_CONFIG.get("header_markers"))

COMPANY_OWNED = _lower_set(COMPANY_CONFIG.get("owned_domains"))
MAIL_INFRA = _lower_set(COMPANY_CONFIG.get("mail_infrastructure"))
TRUSTED_PARTNERS = _lower_set(COMPANY_CONFIG.get("trusted_partners"))
HIGH_RISK_TLDS = _lower_set(COMPANY_CONFIG.get("high_risk_tlds"))
REPORT_MAILBOX = str(COMPANY_CONFIG.get("report_mailbox", "")).strip().lower()

# Extensiile periculoase: executabile + macro + arhive. Arhivele lipseau, deci
# .iso si .img nu erau semnalate deloc - livrarea de malware prin ISO trece fix
# pe langa filtrele care se uita doar la .exe.
SUSPECT_EXTENSIONS = {
    f".{ext.lstrip('.')}"
    for key in ("executable_extensions", "macro_enabled_extensions", "archive_extensions")
    for ext in _lower_set(ATTACHMENT_CONFIG.get(key))
}

_pattern = ATTACHMENT_CONFIG.get("suspicious_double_extension_pattern")
DOUBLE_EXT_RE = re.compile(str(_pattern), re.IGNORECASE) if _pattern else None


# ---------------------------------------------------------------------------
# Ponderi: verdictul e o functie de dovezi
# ---------------------------------------------------------------------------

# Un singur loc pentru toate ponderile, ca sa poti citi politica de decizie
# dintr-o privire si sa o poti calibra fara sa umbli prin reguli.
#
# 1.0 = suficient singur pentru MALICIOUS. Sub 1.0 = are nevoie de coroborare.
SIGNAL_WEIGHT: dict[str, float] = {
    # semnale decisive
    "AUTH_FAILURE": 1.0,
    "SUSPECT_ATTACHMENT": 1.0,
    "INTERNAL_DOMAIN_SPOOF": 1.0,
    # semnale tari, dar nu decisive singure
    "LOOKALIKE_DOMAIN": 0.7,
    "HOMOGLYPH_DOMAIN": 0.7,
    "ENCRYPTED_ARCHIVE": 0.5,
    # semnale medii
    "PUNYCODE_DOMAIN": 0.4,
    "DISPLAY_NAME_MISMATCH": 0.4,
    "LINK_TEXT_MISMATCH": 0.4,
    "REPLY_TO_MISMATCH": 0.3,
    "RETURN_PATH_MISMATCH": 0.3,
    # semnale de continut: pondere mica, dar coroboranta (sectiunea 6.3)
    "CREDENTIAL_REQUEST": 0.25,
    "HIGH_RISK_TLD": 0.2,
    "ARTIFICIAL_URGENCY": 0.15,
    # pur informative: NU au voie sa mute verdictul
    "HIDDEN_TEXT": 0.0,
    "SCREENSHOT_ONLY": 0.0,
    "REPORT_WITHOUT_ORIGINAL": 0.0,
    "MARKETING_CONTENT": 0.0,
    "LEGIT_NEWSLETTER": 0.0,
    "PASS_ALL_CHECKS": 0.0,
    "CYBEREADY_SIMULATION": 0.0,
    "INSUFFICIENT_EVIDENCE": 0.0,
    "CORROBORATED_SIGNALS": 0.0,
}

MALICIOUS_THRESHOLD = 1.0
REVIEW_THRESHOLD = 0.4


# ---------------------------------------------------------------------------
# Ajutoare
# ---------------------------------------------------------------------------


def extract_email_address(raw_from: str) -> str:
    """Adresa curata din headerul From, prin email.utils.parseaddr."""
    if not raw_from:
        return ""
    _, addr = email.utils.parseaddr(raw_from)
    return addr.strip().lower() if addr else raw_from.strip().lower()


def _domain_of(raw_address: str) -> str:
    addr = extract_email_address(raw_address)
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def _comparable_domain(host: str) -> str:
    """Domeniul inregistrabil, sau hostname-ul brut cand sufixul nu e public.

    registered_domain() intoarce sir gol pentru sufixe care nu sunt in lista
    publica (.tld, .local, nume interne). Daca am compara sirurile goale intre
    ele, doua domenii complet diferite ar parea identice, iar un expeditor pe un
    sufix necunoscut ar trece nesemnalat prin TOATE regulile de potrivire - fix
    invers decat vrem de la ele.
    """
    if not host:
        return ""
    return registered_domain(host) or host.strip().lower()


def _matches_any(domain: str, parents: set[str]) -> bool:
    return bool(domain) and any(is_subdomain_of(domain, p) for p in parents)


def _auth_failed(auth_results: str) -> bool:
    lowered = auth_results.lower()
    return any(f"{m}=fail" in lowered for m in ("spf", "dkim", "dmarc"))


def _url_hosts(parsed: ParsedEmail) -> set[str]:
    hosts = set()
    for url in parsed.urls:
        host = urlparse(url).netloc.lower().split("@")[-1].split(":")[0]
        if host:
            hosts.add(host)
    return hosts


# ---------------------------------------------------------------------------
# Fingerprint CyberReady (sectiunea 6.3, precizie 100%)
# ---------------------------------------------------------------------------


def is_cybeready_simulation(parsed: ParsedEmail) -> bool:
    """Simulare autorizata? Domeniul singur NU e niciodata suficient.

    Lista de domenii sta in `config/cyberready.yaml`, care e public in repo.
    Oricine poate pune `hp@notificaton.online` in From-ul unui phishing real, iar
    forward-urile inline - formatul principal de raportare - nu au
    Authentication-Results, deci nici garda de spf=fail nu ajuta acolo.

    De aceea semnalele sunt impartite in doua clase:

    - TARI: Message-ID / In-Reply-To / References cu sufixul platformei,
      identitatea DKIM din Authentication-Results, IP-ul de expeditie din
      lantul Received, headerele proprietare (X-CRPS, X-Virtual-MTA). Toate
      sunt greu de falsificat sau nu supravietuiesc unui forward.
    - SLABE: hostname de tracking in URL-uri. Un link il pune oricine in corpul
      mailului, deci confirma un expeditor deja plauzibil, nu decide singur.

    Reguli: domeniu cunoscut + orice semnal, sau niciun domeniu + un semnal tare.
    """
    if _auth_failed(parsed.auth_results):
        return False

    auth_lower = (parsed.auth_results or "").lower()
    domain = _domain_of(parsed.from_address)
    domain_match = _matches_any(domain, CYBEREADY_DOMAINS)

    msgid_text = " ".join(
        (parsed.message_id or "", parsed.in_reply_to or "", parsed.references or "")
    ).lower()
    has_msgid = any(suf in msgid_text for suf in CYBEREADY_MSG_ID_SUFFIXES)
    has_auth_identity = any(suf in auth_lower for suf in CYBEREADY_MSG_ID_SUFFIXES)

    received_text = " ".join(parsed.received_chain).lower()
    has_ip = any(ip in received_text or ip in auth_lower for ip in CYBEREADY_IPS)

    header_names = {name.lower() for name in parsed.header_names}
    has_platform_header = any(m in header_names for m in CYBEREADY_HEADER_MARKERS)

    strong = has_msgid or has_auth_identity or has_ip or has_platform_header

    # Semnal slab: hostname de tracking, comparat pe domeniu inregistrabil.
    # `is_subdomain_of` face potrivire pe eticheta, nu pe sufix de text, deci
    # "inner.website.evil.ru" nu trece drept "inner.website".
    hosts = _url_hosts(parsed)
    weak = any(is_subdomain_of(h, t) for h in hosts for t in CYBEREADY_TRACKING_HOSTS)

    return (domain_match and (strong or weak)) or strong


# ---------------------------------------------------------------------------
# Semnale de continut (sectiunea 6.3: pondere mica, dar coroboranta)
# ---------------------------------------------------------------------------

URGENCY_RE = re.compile(
    r"(urgent|imediat|in cel mai scurt timp|[îi]n 24 de ore|expir[ăa]|suspenda|"
    r"blocat|ultima [șs]ans[ăa]|ac[țt]iona[țt]i acum|termen limit[ăa]|"
    r"immediately|within 24 hours|act now|final notice)",
    re.IGNORECASE,
)

CREDENTIAL_RE = re.compile(
    r"(parol[ăa]|password|date de autentificare|credentiale|credential|"
    r"confirma[țt]i contul|reactiva[țt]i contul|verifica[țt]i contul|"
    r"autentifica[țt]i-v[ăa]|conecta[țt]i-v[ăa]|sign in|log ?in|verify your account)",
    re.IGNORECASE,
)

MARKETING_RE = re.compile(
    r"(publicitate|eveniment|conferin[țt][ăa]|invita[țt]ie|simpozion|webinar|"
    r"promo[țt]ie|reducere|ofert[ăa] special[ăa]|newsletter)",
    re.IGNORECASE,
)

UNSUBSCRIBE_RE = re.compile(r"(dezabon|unsubscribe|opt[- ]?out)", re.IGNORECASE)

# Text ascuns in HTML: alb pe alb, 1px, display:none, vizibilitate zero.
HIDDEN_STYLE_RE = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*[01](\.\d+)?px|"
    r"opacity\s*:\s*0(\.0+)?\b|color\s*:\s*#f{3,6}\b)",
    re.IGNORECASE,
)
INVISIBLE_CHARS = ("​", "‌", "‍", "‮", "⁠", "﻿")

# Un token care arata a domeniu, folosit in textul ancorei sau in display-name.
DOMAIN_TOKEN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", re.I)


# ---------------------------------------------------------------------------
# Colectarea dovezilor
# ---------------------------------------------------------------------------


def _auth_evidence(parsed: ParsedEmail) -> list[Evidence]:
    if _auth_failed(parsed.auth_results):
        return [
            Evidence(
                code="AUTH_FAILURE",
                severity=Severity.CRITICAL,
                description="Verificarea autenticității e-mailului a eșuat (SPF/DKIM/DMARC).",
                detail=defang(parsed.auth_results),
            )
        ]

    lowered = (parsed.auth_results or "").lower()
    if all(f"{m}=pass" in lowered for m in ("spf", "dkim", "dmarc")):
        return [
            Evidence(
                code="PASS_ALL_CHECKS",
                severity=Severity.INFO,
                description="Autentificarea expeditorului a trecut integral (SPF, DKIM, DMARC).",
            )
        ]
    return []


def _attachment_evidence(parsed: ParsedEmail) -> list[Evidence]:
    found: list[Evidence] = []
    for att in parsed.attachments:
        filename = att.filename.lower()
        ext = f".{filename.rsplit('.', 1)[-1]}" if "." in filename else ""
        final_ext_is_suspect = ext in SUSPECT_EXTENSIONS

        # Dubla extensie conteaza doar cand extensia FINALA e periculoasa:
        # "pare document, dar e executabil". Altfel raport.xls.pdf si
        # poza.jpg.png ies malitioase, ceea ce e absurd.
        double_ext = bool(DOUBLE_EXT_RE and DOUBLE_EXT_RE.search(filename))

        if final_ext_is_suspect:
            reason = (
                f"dublă extensie ({att.filename})"
                if double_ext
                else f"extensie periculoasă ({ext})"
            )
            found.append(
                Evidence(
                    code="SUSPECT_ATTACHMENT",
                    severity=Severity.CRITICAL,
                    description=f"Atașament cu risc de securitate ridicat: {reason}.",
                    detail=defang(f"SHA256: {att.sha256}"),
                )
            )

        if att.encrypted_archive:
            found.append(
                Evidence(
                    code="ENCRYPTED_ARCHIVE",
                    severity=Severity.HIGH,
                    description=(
                        f"Arhivă protejată cu parolă: {att.filename}. "
                        "Conținutul nu poate fi scanat automat."
                    ),
                    detail=defang(f"SHA256: {att.sha256}"),
                )
            )
    return found


def _header_consistency_evidence(parsed: ParsedEmail) -> list[Evidence]:
    """D1 + D2: Reply-To si Return-Path care nu corespund cu From.

    Ambele campuri erau deja parsate si nu le citea nimeni. Sunt cele mai ieftine
    semnale din toata lista.
    """
    found: list[Evidence] = []
    from_domain = _comparable_domain(_domain_of(parsed.from_address))
    if not from_domain:
        return found

    # Pe listele de mail, Return-Path e adresa de bounce a platformei si difera
    # legitim de From. Nu semnalam acolo.
    is_mailing_list = any(
        name in {"list-unsubscribe", "list-id"} for name in parsed.header_names
    )

    reply_domain = _comparable_domain(_domain_of(parsed.reply_to))
    if reply_domain and reply_domain != from_domain:
        found.append(
            Evidence(
                code="REPLY_TO_MISMATCH",
                severity=Severity.MEDIUM,
                description="Răspunsul ar pleca către alt domeniu decât cel al expeditorului.",
                detail=defang(f"From: {from_domain}, Reply-To: {reply_domain}"),
            )
        )

    return_domain = _comparable_domain(_domain_of(parsed.return_path))
    if return_domain and return_domain != from_domain and not is_mailing_list:
        found.append(
            Evidence(
                code="RETURN_PATH_MISMATCH",
                severity=Severity.MEDIUM,
                description="Traseul de retur nu corespunde cu domeniul din From.",
                detail=defang(f"From: {from_domain}, Return-Path: {return_domain}"),
            )
        )
    return found


def _display_name_evidence(parsed: ParsedEmail) -> list[Evidence]:
    """D4: clasicul `From: "Banca X" <atacator@rau.tld>`.

    Doua tipare: display-name-ul contine un domeniu care nu e al expeditorului,
    sau contine numele unui domeniu propriu / de partener fara sa vina de acolo.
    """
    display = parsed.from_display_name.strip()
    from_domain = _comparable_domain(_domain_of(parsed.from_address))
    if not display or not from_domain:
        return []

    claimed = ""
    match = DOMAIN_TOKEN_RE.search(display)
    if match and _comparable_domain(match.group(1)) not in ("", from_domain):
        claimed = _comparable_domain(match.group(1))
    else:
        words = {w for w in re.split(r"[^a-z0-9]+", display.lower()) if len(w) > 3}
        for known in COMPANY_OWNED | TRUSTED_PARTNERS:
            label = known.split(".")[0]
            if label in words and _comparable_domain(known) != from_domain:
                claimed = known
                break

    if not claimed:
        return []

    return [
        Evidence(
            code="DISPLAY_NAME_MISMATCH",
            severity=Severity.MEDIUM,
            description="Numele afișat al expeditorului nu corespunde cu domeniul real.",
            detail=defang(f'Afișat: "{display}" ({claimed}), real: {from_domain}'),
        )
    ]


def _domain_evidence(parsed: ParsedEmail) -> list[Evidence]:
    """Spoofing intern, lookalike, homoglife/punycode si TLD cu risc ridicat."""
    found: list[Evidence] = []
    sender_domain = _domain_of(parsed.from_address)
    if not sender_domain:
        return found

    claims_owned = _matches_any(sender_domain, COMPANY_OWNED)

    # 5a. Pretinde un domeniu propriu, dar nu a trecut prin infra proprie.
    #
    # Se poate verifica DOAR cand From si Received vin din acelasi mesaj. La un
    # forward inline, From vine din corp iar Received e al colegului care a
    # raportat - a compara cele doua inseamna a pune intrebarea "a trecut prin
    # infra noastra?" pe lantul gresit.
    if claims_owned and not parsed.headers_from_body:
        received_text = " ".join(parsed.received_chain).lower()
        if not any(host in received_text for host in MAIL_INFRA):
            found.append(
                Evidence(
                    code="INTERNAL_DOMAIN_SPOOF",
                    severity=Severity.CRITICAL,
                    description=(
                        "Expeditorul pretinde un domeniu propriu, dar mesajul nu a trecut "
                        "prin infrastructura de mail internă."
                    ),
                    detail=defang(f"Domeniu: {sender_domain}"),
                )
            )

    # 5b. Lookalike - are sens NUMAI pentru domenii care nu sunt ale noastre.
    # Domeniile proprii seamana intre ele: distanta dintre "exemplu.com" si
    # "exemplu.ro" e 2, deci varianta veche marca orice mail intern ca malitios.
    if not claims_owned:
        for owned in COMPANY_OWNED:
            if _levenshtein(sender_domain, owned) <= 2:
                found.append(
                    Evidence(
                        code="LOOKALIKE_DOMAIN",
                        severity=Severity.HIGH,
                        description=(
                            f"Domeniul expeditorului seamănă cu un domeniu propriu "
                            f"({owned}), dar nu este identic."
                        ),
                        detail=defang(f"Domeniu raportat: {sender_domain}"),
                    )
                )
                break

    found.extend(_homoglyph_evidence(sender_domain, parsed))

    # 5c. TLD cu risc ridicat: indiciu slab, nu dovada. Ramane MEDIUM si cu
    # pondere mica - nu poti condamna un expeditor doar pentru ca e pe .online.
    tld = f".{sender_domain.rsplit('.', 1)[-1]}" if "." in sender_domain else ""
    if tld in HIGH_RISK_TLDS:
        found.append(
            Evidence(
                code="HIGH_RISK_TLD",
                severity=Severity.MEDIUM,
                description=f"Domeniul expeditorului folosește un TLD cu risc ridicat ({tld}).",
                detail=defang(f"Domeniu: {sender_domain}"),
            )
        )
    return found


def _homoglyph_evidence(sender_domain: str, parsed: ParsedEmail) -> list[Evidence]:
    """D3: homoglife si punycode / IDN.

    Levenshtein nu prinde asa ceva: un chirilic "\u0430" in loc de "a" latin are
    distanta 0 la nivel de aspect si mare la nivel de bytes. Un domeniu `xn--`
    ascunde acelasi lucru, doar codat.
    """
    found: list[Evidence] = []
    candidates = {sender_domain} | _url_hosts(parsed)

    for host in sorted(c for c in candidates if c):
        if host.startswith("xn--") or ".xn--" in host:
            found.append(
                Evidence(
                    code="PUNYCODE_DOMAIN",
                    severity=Severity.MEDIUM,
                    description="Domeniu codat punycode (IDN), care poate imita un nume cunoscut.",
                    detail=defang(f"Domeniu: {host}"),
                )
            )
            continue
        try:
            dangerous = bool(confusables.is_dangerous(host))
        except (ValueError, UnicodeError):
            dangerous = False
        if dangerous:
            found.append(
                Evidence(
                    code="HOMOGLYPH_DOMAIN",
                    severity=Severity.HIGH,
                    description=(
                        "Domeniul amestecă alfabete diferite (homoglife) și imită vizual "
                        "un nume legitim."
                    ),
                    detail=defang(f"Domeniu: {host}"),
                )
            )
    return found


def _content_evidence(parsed: ParsedEmail) -> list[Evidence]:
    """D5: urgenta artificiala, cereri de credentiale, discrepanta text-link."""
    found: list[Evidence] = []
    text = f"{parsed.subject}\n{parsed.body_text}"

    if URGENCY_RE.search(text):
        found.append(
            Evidence(
                code="ARTIFICIAL_URGENCY",
                severity=Severity.LOW,
                description="Mesajul creează presiune de timp (urgență artificială).",
            )
        )

    if CREDENTIAL_RE.search(text):
        found.append(
            Evidence(
                code="CREDENTIAL_REQUEST",
                severity=Severity.MEDIUM,
                description="Mesajul cere date de autentificare sau trimite către o pagină de logare.",
            )
        )

    for link in parsed.links:
        match = DOMAIN_TOKEN_RE.search(link.text)
        if not match:
            continue
        shown = _comparable_domain(match.group(1))
        real = _comparable_domain(urlparse(link.href).netloc.split(":")[0])
        if shown and real and shown != real:
            found.append(
                Evidence(
                    code="LINK_TEXT_MISMATCH",
                    severity=Severity.MEDIUM,
                    description="Textul unui link arată alt domeniu decât cel către care duce.",
                    detail=defang(f"Afișat: {shown}, real: {real}"),
                )
            )
            break

    return found


def _hidden_text_evidence(parsed: ParsedEmail) -> list[Evidence]:
    """Text ascuns: se consemneaza, dar NU misca verdictul (pondere 0).

    Cerinta cazului 08 e ca verdictul produs cu si fara textul ascuns sa fie
    identic. Varianta veche facea din caracterele ascunse chiar MOTIVUL
    verdictului MALICIOUS - adica exact ce cerinta interzice. In plus, un
    zero-width sau un preheader display:none sunt banale in mailurile de
    marketing, deci regula producea falsi pozitivi cu duiumul.

    Curatarea reala se face in `sanitize_for_model`, inainte ca textul sa ajunga
    la model. Aici doar lasam urma pentru analist.
    """
    has_invisible = any(ch in parsed.body_text for ch in INVISIBLE_CHARS)
    has_hidden_style = bool(HIDDEN_STYLE_RE.search(parsed.body_html))
    if not (has_invisible or has_hidden_style):
        return []

    kinds = []
    if has_invisible:
        kinds.append("caractere invizibile")
    if has_hidden_style:
        kinds.append("text ascuns prin stil (display:none / 1px / alb pe alb)")

    return [
        Evidence(
            code="HIDDEN_TEXT",
            severity=Severity.INFO,
            description=(
                "Mesajul conține text ascuns. Informativ: nu influențează verdictul, "
                "dar este eliminat înainte de a ajunge la model."
            ),
            detail="; ".join(kinds),
        )
    ]


def _classification_evidence(parsed: ParsedEmail) -> list[Evidence]:
    """Newsletter de partener de incredere si continut de marketing."""
    found: list[Evidence] = []
    sender_domain = _domain_of(parsed.from_address)
    from_addr = extract_email_address(parsed.from_address)
    text = f"{parsed.subject}\n{parsed.body_text}"
    link_text = " ".join(link.text for link in parsed.links)

    has_unsubscribe = bool(
        UNSUBSCRIBE_RE.search(text)
        or UNSUBSCRIBE_RE.search(link_text)
        or "list-unsubscribe" in parsed.header_names
    )
    is_trusted = _matches_any(sender_domain, TRUSTED_PARTNERS)

    if is_trusted and not _auth_failed(parsed.auth_results) and has_unsubscribe:
        found.append(
            Evidence(
                code="LEGIT_NEWSLETTER",
                severity=Severity.LOW,
                description="Newsletter legitim de la un partener de încredere (furnizor cunoscut).",
                detail=defang(f"Expeditor: {from_addr}, Subiect: {parsed.subject}"),
            )
        )
    elif MARKETING_RE.search(text) or has_unsubscribe:
        found.append(
            Evidence(
                code="MARKETING_CONTENT",
                severity=Severity.LOW,
                description=(
                    "Conținut comercial nesolicitat: promoții, evenimente sau newsletter "
                    "fără abonament cunoscut."
                ),
                detail=defang("Elemente de marketing, fără risc direct de malware."),
            )
        )

    return found


def _report_form_evidence(parsed: ParsedEmail) -> list[Evidence]:
    """Forma raportarii, cand ea insasi e motivul escaladarii."""
    if parsed.report_kind == ReportKind.SCREENSHOT_ONLY:
        return [
            Evidence(
                code="SCREENSHOT_ONLY",
                severity=Severity.MEDIUM,
                description="Raportul conține doar o captură de ecran și necesită revizuire manuală.",
            )
        ]
    return []


def _original_message_available(parsed: ParsedEmail) -> bool:
    """A reusit parser-ul sa scoata mesajul ORIGINAL din raportare?"""
    return parsed.report_kind == ReportKind.ATTACHED_EML or parsed.headers_from_body


def is_report_wrapper(parsed: ParsedEmail) -> bool:
    """Analizam invelisul raportarii in loc de mailul suspect?

    Cand un coleg trimite o captura de ecran sau descrie in cuvinte ce a primit,
    singurele headere din mesaj sunt ALE LUI. A rula pe ele regulile de
    autenticitate a expeditorului inseamna a-l acuza pe raportor: From-ul lui e
    pe un domeniu propriu, iar Received-ul nu trece prin infrastructura interna,
    deci iese INTERNAL_DOMAIN_SPOOF pe cel mai cuminte om din companie.

    `report_mailbox` din config exista exact pentru asta si nu il citea nimeni:
    "Mesajele CATRE ea sunt raportari; nu se analizeaza wrapper-ul, ci mesajul
    original din interior." Daca originalul nu s-a putut extrage, nu exista ce
    analiza - si atunci raspunsul corect e escaladarea, nu un verdict inventat
    din datele raportorului.
    """
    if _original_message_available(parsed):
        return False
    if parsed.report_kind == ReportKind.SCREENSHOT_ONLY:
        return True
    return bool(REPORT_MAILBOX) and REPORT_MAILBOX in set(parsed.to_addresses)


# Regulile care judeca EXPEDITORUL. Pe un invelis de raportare, expeditorul e
# colegul care raporteaza, deci nu au ce cauta acolo.
SENDER_RULES = (
    _auth_evidence,
    _domain_evidence,
    _header_consistency_evidence,
    _display_name_evidence,
)

# Regulile care judeca CONTINUTUL. Pe un invelis, continutul e textul scris de
# coleg - "descrierea NU e o sursa de verdict" (nota cazului 11).
CONTENT_RULES = (
    _content_evidence,
    _hidden_text_evidence,
    _classification_evidence,
)

# Atasamentele raman: un coleg poate redirectiona chiar fisierul periculos.
ALWAYS_RULES = (_attachment_evidence, _report_form_evidence)


def _collect_evidence(parsed: ParsedEmail) -> list[Evidence]:
    """Toate regulile, fara iesire devreme. Asa se coroboreaza semnalele."""
    evidence: list[Evidence] = []

    if is_report_wrapper(parsed):
        for rule in ALWAYS_RULES:
            evidence.extend(rule(parsed))
        evidence.append(
            Evidence(
                code="REPORT_WITHOUT_ORIGINAL",
                severity=Severity.MEDIUM,
                description=(
                    "Raportare din care mesajul original nu a putut fi extras. "
                    "Nu există dovezi tehnice de analizat, deci decide un analist."
                ),
                detail="Headerele disponibile aparțin colegului care a raportat, nu expeditorului.",
            )
        )
        return evidence

    for rule in ALWAYS_RULES + SENDER_RULES + CONTENT_RULES:
        evidence.extend(rule(parsed))
    return evidence


# ---------------------------------------------------------------------------
# Decizia
# ---------------------------------------------------------------------------


def score_of(evidence: list[Evidence]) -> float:
    return round(sum(SIGNAL_WEIGHT.get(ev.code, 0.0) for ev in evidence), 3)


def _decide(evidence: list[Evidence]) -> Analysis:
    codes = {ev.code for ev in evidence}

    if "CYBEREADY_SIMULATION" in codes:
        return Analysis(verdict=Verdict.SIMULATION, confidence=1.0, evidence=evidence)

    score = score_of(evidence)

    if score >= MALICIOUS_THRESHOLD:
        confidence = 0.95 if "SUSPECT_ATTACHMENT" in codes else 0.9
        return Analysis(verdict=Verdict.MALICIOUS, confidence=confidence, evidence=evidence)

    if score < REVIEW_THRESHOLD:
        # Ordinea conteaza: un newsletter legitim are si el buton de dezabonare,
        # deci ar cadea pe MARKETING_CONTENT daca l-am verifica primul.
        if "LEGIT_NEWSLETTER" in codes:
            return Analysis(verdict=Verdict.LEGITIMATE, confidence=0.85, evidence=evidence)
        if "MARKETING_CONTENT" in codes:
            return Analysis(verdict=Verdict.SPAM, confidence=0.85, evidence=evidence)
        if "PASS_ALL_CHECKS" in codes:
            return Analysis(verdict=Verdict.LEGITIMATE, confidence=0.85, evidence=evidence)
    else:
        evidence.append(
            Evidence(
                code="CORROBORATED_SIGNALS",
                severity=Severity.MEDIUM,
                description=(
                    "Mai multe semnale slabe se coroborează fără să atingă pragul de "
                    "verdict automat. Necesită decizia unui analist."
                ),
                detail=f"Scor cumulat: {score:.2f} (prag automat: {MALICIOUS_THRESHOLD:.2f})",
            )
        )
        return Analysis(verdict=Verdict.NEEDS_REVIEW, confidence=0.6, evidence=evidence)

    if not evidence:
        evidence.append(
            Evidence(
                code="INSUFFICIENT_EVIDENCE",
                severity=Severity.MEDIUM,
                description="E-mailul nu conține suficiente semnale clare și necesită analiză manuală.",
            )
        )
    return Analysis(verdict=Verdict.NEEDS_REVIEW, confidence=0.5, evidence=evidence)


def analyze(parsed: ParsedEmail) -> Analysis:
    """Verdictul, ca functie de dovezi.

    Fingerprint-ul de simulare se evalueaza primul si scurtcircuiteaza restul:
    un mail de training nu trebuie sa fie judecat dupa regulile de phishing, iar
    domeniile platformei cad si ele sub TLD-urile cu risc ridicat.
    """
    if is_cybeready_simulation(parsed):
        return Analysis(
            verdict=Verdict.SIMULATION,
            confidence=1.0,
            evidence=[
                Evidence(
                    code="CYBEREADY_SIMULATION",
                    severity=Severity.INFO,
                    description="E-mailul este o simulare autorizată CyberReady.",
                    detail=defang(f"Expeditor: {extract_email_address(parsed.from_address)}"),
                )
            ],
        )

    return _decide(_collect_evidence(parsed))


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
