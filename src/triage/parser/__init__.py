"""Extrage mesajul ORIGINAL, nu wrapper-ul colegului care a raportat."""

from __future__ import annotations
import hashlib
import re
from re import Match
from dataclasses import dataclass, field
from email import message_from_bytes
from enum import StrEnum
from bs4 import BeautifulSoup
from email.message import Message
from email.header import decode_header
import base64
import urllib.parse
import quopri
from contextlib import suppress

class ReportKind(StrEnum):
    FORWARD_INLINE = "FORWARD_INLINE"
    ATTACHED_EML = "ATTACHED_EML"
    SCREENSHOT_ONLY = "SCREENSHOT_ONLY"  # -> NEEDS_REVIEW
    UNKNOWN = "UNKNOWN"
    SPAM="SPAM"


@dataclass(slots=True)
class ParsedAttachment:
    filename: str
    sha256: str
    mime_type: str
    size: int


@dataclass(slots=True)
class ParsedEmail:
    report_kind: ReportKind
    subject: str = ""
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    message_id: str = ""
    in_reply_to: str = ""
    references: str = ""
    auth_results: str = ""
    received_chain: list[str] = field(default_factory=list)
    body_text: str = ""
    urls: list[str] = field(default_factory=list)
    attachments: list[ParsedAttachment] = field(default_factory=list)

def _clean_body_text(raw_text: str) -> str:
    """Elimină headerele reziduale scapate în corp din cauza e-mailurilor malformate."""
    # TODO(bug 1 din 2): functia sterge un URL aflat pe prima linie a corpului.
    # Ce e gresit: bucla de mai jos sterge orice linie de la inceput care contine
    # ":", iar un URL contine ":" in "https://". Testat:
    #   in : 'https://evil.example/login\nVa rugam confirmati contul.'
    #   out: 'Va rugam confirmati contul.'
    # Extragerea de URL-uri se face pe textul deja curatat, deci link-ul dispare
    # complet din parsed.urls. Intr-un analizor de phishing, sa pierzi link-ul e
    # chiar lucrul pe care nu ti-l permiti. La fel se pierde si un rand de tipul
    # "Atentie: contul dvs...".
    #
    # TODO(bug 2 din 2): functia mananca blocul de headere de care are nevoie
    # extract_forwarded_headers. Un forward din Outlook incepe fix cu "From:",
    # "Sent:", "To:", "Subject:", deci curatarea sterge exact ce cauta regex-ul
    # dupa aceea. Vezi TODO-ul de la extract_forwarded_headers.
    #
    # Cum rezolvi ambele: nu sterge orice linie cu ":". Foloseste un regex care
    # recunoaste un header adevarat, ceva de genul ^[A-Za-z][A-Za-z0-9-]*:\s
    # Un URL nu se potriveste, pentru ca dupa "https" vine "://", nu ": ".
    lines = raw_text.splitlines()
    cleaned_lines = []
    in_headers = True

    for line in lines:
        if in_headers:
            if ":" in line and not line.startswith(" "):
                continue
            if line.strip().startswith("X-") or "Content-Type" in line:
                continue
            if not line.strip():
                in_headers = False
                continue
            in_headers = False

        cleaned_lines.append(line)

    return "\n".join(cleaned_lines).strip()

def _decode_part_payload(part: Message) -> str:
    """Decodează payload-ul unei părți având grijă de Quoted-Printable și Charset."""
    payload = part.get_payload(decode=True)
    if not payload or not isinstance(payload, bytes):
        return ""

    cte = str(part.get("Content-Transfer-Encoding", "")).lower()
    if cte == "quoted-printable":
        with suppress(Exception):
            payload = quopri.decodestring(payload)
        

    charset = part.get_content_charset() or "utf-8"

    for enc in [charset, "utf-8", "iso-8859-1", "windows-1250"]:
        try:
            return payload.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue

    return payload.decode("utf-8", errors="replace")

def decode_mime_header(header_value: str | None) -> str:
    if not header_value:
        return ""

    text = str(header_value)

    with suppress(Exception):
        parts = decode_header(text)
        decoded_chunks = []
        for fragment, encoding in parts:
            if isinstance(fragment, bytes):
                charset = encoding or "utf-8"
                try:
                    decoded_chunks.append(
                        fragment.decode(charset, errors="replace")
                    )
                except (UnicodeDecodeError, LookupError):
                    decoded_chunks.append(
                        fragment.decode("iso-8859-1", errors="replace")
                    )
            else:
                decoded_chunks.append(str(fragment))
        text = " ".join(decoded_chunks) 
    
    def decode_b64(match: Match[str]) -> str:
        b64_str = match.group(1).strip()
        b64_str = re.sub(r"[^A-Za-z0-9+/=]", "", b64_str)
        missing_padding = len(b64_str) % 4
        if missing_padding:
            b64_str += "=" * (4 - missing_padding)
        try:
            return base64.b64decode(b64_str).decode("utf-8", errors="replace")
        except Exception:
            return match.group(0)

    def decode_qp(match: Match[str]) -> str:
        qp_str = match.group(1).replace("_", " ")
        url_encoded = re.sub(r"=([0-9A-Fa-f]{2})", r"%\1", qp_str)
        try:
            return urllib.parse.unquote(
                url_encoded, encoding="utf-8", errors="replace"
            )
        except Exception:
            return match.group(0)

    text = re.sub(r"=\?[uU][tT][fF]-8\?[bB]\?([^?]*)\?=", decode_b64, text)
    text = re.sub(r"=\?[uU][tT][fF]-8\?[qQ]\?([^?]*)\?=", decode_qp, text)

    # TODO(bug): cele doua transformari de mai jos strica subiecte perfect normale.
    # Ce e gresit: decode_header() din biblioteca standard, apelat mai sus, a facut
    # deja treaba corect. Aici se mai trece inca o data peste rezultat cu "_" -> spatiu
    # si "=XX" -> procent-decodare. Alea au sens DOAR in interiorul unui encoded-word
    # de tip =?utf-8?q?...?=, nu pe text deja decodat. Testat:
    #   'Raport_final_2026'          -> 'Raport final 2026'
    #   'Reducere 100%20 la produse' -> 'Reducere 100 la produse'
    # Cum rezolvi: muta cele doua transformari in interiorul functiei decode_qp,
    # care trateaza deja ramura =?utf-8?q?. Pe textul deja decodat nu mai aplica nimic.
    # Pont general: daca biblioteca standard a facut deja treaba, nu mai treci inca
    # o data peste rezultat cu regex - de obicei strici, nu repari.
    text = text.replace("_", " ")
    text = re.sub(r"=([0-9A-Fa-f]{2})", r"%\1", text)
    
    with suppress(Exception):
           text= urllib.parse.unquote(text, encoding="utf-8", errors="replace")

    text = re.sub(r"\s+=\s+", " ", text)
    return re.sub(r"\s+", " ", text).strip()

_FWD_HEADER_BLOCK_RE = re.compile(
    r"(?:From|De la)\s*:\s*(?P<from>.+?)\n"
    r"(?:Sent|Trimis|Date|Data)\s*:\s*.+?\n"
    r"(?:To|Către|Catre)\s*:\s*.+?\n"
    r"(?:Subject|Subiect)\s*:\s*(?P<subject>.+?)\n",
    re.IGNORECASE,
)
def extract_forwarded_headers(body_text: str) -> dict[str, str]:
    """Extrage blocul de headere inline dintr-un forward. Best-effort:
    e text scris de client de mail, nu structurat ca un Message."""
    # TODO(bug): functia asta si _clean_body_text se bat cap in cap, si din cauza
    # asta extragerea merge doar din intamplare.
    # Ce e gresit: in parse_report, functia e chemata pe full_body, adica pe textul
    # DEJA trecut prin _clean_body_text. Iar _clean_body_text sterge liniile de la
    # inceput care contin ":" - exact "From:", "Sent:", "To:", "Subject:". Deci pe
    # un forward din Outlook, care incepe direct cu blocul de headere, nu mai ramane
    # nimic de extras. Testat:
    #   extract pe corpul BRUT     -> {'from': 'Atacator <fake@rau.com>', ...}
    #   dupa _clean_body_text      -> 'Corp original aici.'
    #   extract pe corpul CURATAT  -> {}
    # Pe tot pipeline-ul, from_address ramane al colegului care a raportat, nu al
    # atacatorului. Regex-ul functioneaza doar cand exista text inaintea blocului.
    # Cum rezolvi: cheama extract_forwarded_headers pe textul decodat INAINTE de
    # _clean_body_text. Tine textul brut intr-o variabila separata, extrage
    # headerele din el, si abia apoi curata pentru body_text.
    match = _FWD_HEADER_BLOCK_RE.search(body_text)
    if not match:
        return {}
    return {
        "from": match.group("from").strip(),
        "subject": match.group("subject").strip(),
    }

def detect_report_kind(raw: bytes) -> ReportKind:
    msg = message_from_bytes(raw)
    has_image = False
    has_text = False
    for part in msg.walk():
        content_type = part.get_content_type()
        filename = part.get_filename() or ""
        if content_type == "message/rfc822" or filename.lower().endswith(".eml"):
            return ReportKind.ATTACHED_EML
        if content_type.startswith("image/"):
            has_image = True
        elif content_type == "text/plain":
            body = part.get_payload(decode=True)
            if isinstance(body, bytes) and body.strip():
                has_text = True
    if has_image and not has_text:
        return ReportKind.SCREENSHOT_ONLY
    raw_subject = msg.get("Subject", "")
    subject = decode_mime_header(raw_subject)
    if "fwd:" in subject.lower() or "fw:" in subject.lower():
        return ReportKind.FORWARD_INLINE
    return ReportKind.UNKNOWN

def parse_report(raw: bytes) -> ParsedEmail:
    msg = message_from_bytes(raw)
    kind = detect_report_kind(raw)

    if kind == ReportKind.ATTACHED_EML:
        for part in msg.walk():
            content_type = part.get_content_type()
            filename = (part.get_filename() or "").lower()
            if content_type == "message/rfc822" or filename.endswith(".eml"):
                payload = part.get_payload()
                if isinstance(payload, list) and payload:
                    first_item = payload[0]
                    if isinstance(first_item, Message):
                        msg = first_item
                        break
                elif isinstance(payload, Message):
                    msg = payload
                    break
                elif isinstance(payload, bytes):
                    msg = message_from_bytes(payload)
                    break

    raw_subject = msg.get("Subject", "")
    subject = decode_mime_header(raw_subject)

    from_address = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    auth_results = msg.get("Authentication-Results", "")
    message_id = msg.get("Message-ID", "")
    in_reply_to = msg.get("In-Reply-To", "")
    references = msg.get("References", "")
    received_chain = msg.get_all("Received", [])

    body_text_parts = []
    urls = set()
    attachments = []
    url_pattern = re.compile(r"https?://[^\s<>\"']+")

    # TODO(curatenie): corpul buclei e indentat cu 12 spatii in loc de 8. Merge,
    # pentru ca e uniform, dar e derutant la citit. Ruleaza "make fmt".
    # Cat esti acolo: analyzer/__init__.py si parser/__init__.py inca nu au linie
    # noua la final de fisier.
    for part in msg.walk():
            if part.is_multipart():
                continue
    
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
    
            if "attachment" in disposition or part.get_filename():
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    filename = part.get_filename() or "unnamed"
                    sha256 = hashlib.sha256(payload).hexdigest()
                    size = len(payload)
                    attachments.append(
                        ParsedAttachment(
                            filename=filename,
                            sha256=sha256,
                            mime_type=content_type,
                            size=size,
                        )
                    )
                continue
    
            if content_type == "text/plain":
                text = _decode_part_payload(part)
                text = _clean_body_text(text)
                if text:
                    body_text_parts.append(text)
                    for match in url_pattern.findall(text):
                        urls.add(match)
    
            elif content_type == "text/html":
                html_content = _decode_part_payload(part)
                soup = BeautifulSoup(html_content, "html.parser")
    
                # TODO(bug): conditia asta face ca textul din HTML sa fie ignorat
                # aproape mereu. Se extrage doar daca nu exista DELOC o parte
                # text/plain. La un multipart/alternative normal, adica majoritatea
                # mailurilor, partea HTML e sarita complet.
                # Consecinte: (1) regula de prompt injection din analyzer nu vede
                # niciodata textul ascuns din HTML - testat pe un mail de forma
                # cazului 08, textul de injectie nu a ajuns in body_text;
                # (2) cuvintele cheie de marketing de la regula 7 (SPAM) lipsesc si
                # ele, pentru ca in mailurile comerciale textul bun e in HTML.
                # Cum rezolvi: aduna textul din HTML mereu, nu doar ca rezerva.
                # Daca te temi de duplicare cu text/plain, pastreaza-le separat
                # (de exemplu un camp body_html_text) sau deduplica la final.
                if not body_text_parts:
                    for element in soup(["script", "style"]):
                        element.decompose()
                    extracted_text = _clean_body_text(
                        soup.get_text(separator="\n")
                    )
                    if extracted_text:
                        body_text_parts.append(extracted_text)
    
                for a_tag in soup.find_all("a", href=True):
                    urls.add(a_tag["href"])
    
                for match in url_pattern.findall(html_content):
                    urls.add(match)
        

    full_body = "\n\n".join(body_text_parts).strip()

    # TODO(bug): vezi TODO-ul de la extract_forwarded_headers - se cheama pe
    # full_body, adica pe textul deja curatat, care de multe ori nu mai contine
    # blocul de headere.
    #
    # TODO(efect secundar, atentie): dupa ce suprascrii from_address cu expeditorul
    # din forward, received_chain ramane al mesajului invelis (al colegului care a
    # raportat). Adica _check_domain_spoofing din analyzer compara From-ul unui
    # mesaj cu Received-ul altui mesaj - INTERNAL_DOMAIN_SPOOF isi pune intrebarea
    # "a trecut prin infra noastra?" pe lantul gresit.
    # Cum rezolvi: fie salvezi headerele din forward in campuri separate, nu peste
    # cele originale, fie adaugi in ParsedEmail un camp care spune ca from_address
    # vine din corpul mailului, nu din headere, si analyzer-ul tine cont de el.
    if kind == ReportKind.FORWARD_INLINE:
        fwd_headers = extract_forwarded_headers(full_body)
        if fwd_headers.get("from"):
            from_address = fwd_headers["from"]
        if fwd_headers.get("subject"):
            subject = fwd_headers["subject"]

    return ParsedEmail(
        report_kind=kind,
        subject=subject,
        from_address=from_address,
        reply_to=reply_to,
        return_path=return_path,
        auth_results=auth_results,
        message_id=message_id,
        in_reply_to=in_reply_to,
        references=references,
        received_chain=received_chain,
        body_text=full_body,
        urls=list(urls),
        attachments=attachments,
    )