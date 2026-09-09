"""Extrage mesajul ORIGINAL, nu wrapper-ul colegului care a raportat."""

from __future__ import annotations

import base64
import binascii
import email.utils
import hashlib
import io
import quopri
import re
import urllib.parse
import zipfile
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message
from enum import StrEnum
from re import Match

from bs4 import BeautifulSoup, Tag


class ReportKind(StrEnum):
    """CUM a fost raportat mesajul, nu ce este el. Verdictul e treaba analizorului."""

    FORWARD_INLINE = "FORWARD_INLINE"
    ATTACHED_EML = "ATTACHED_EML"
    SCREENSHOT_ONLY = "SCREENSHOT_ONLY"  # -> NEEDS_REVIEW
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class ParsedAttachment:
    filename: str
    sha256: str
    mime_type: str
    size: int
    encrypted_archive: bool = False


@dataclass(slots=True)
class ParsedLink:
    """Textul ancorei impreuna cu href-ul. Fara pereche nu poti face semnalul
    de discrepanta text-link din 6.3."""

    text: str
    href: str


@dataclass(slots=True)
class ParsedEmail:
    report_kind: ReportKind
    subject: str = ""
    # Expeditorul MESAJULUI ORIGINAL - la un forward, atacatorul.
    from_address: str = ""
    from_display_name: str = ""
    # Colegul care a raportat, adica From-ul mesajului-invelis. Draft-ul de
    # raspuns i se adreseaza LUI, nu expeditorului original. Cele doua coincid
    # doar cand mesajul nu e o raportare impachetata.
    reporter_address: str = ""
    reporter_display_name: str = ""
    # Destinatarii mesajului-invelis. Un mesaj catre adresa de raportare e o
    # raportare, nu un mail suspect trimis de coleg.
    to_addresses: list[str] = field(default_factory=list)
    reply_to: str = ""
    return_path: str = ""
    message_id: str = ""
    in_reply_to: str = ""
    references: str = ""
    auth_results: str = ""
    # Data din headerul Date al mesajului-invelis, adica momentul raportarii.
    sent_at: datetime | None = None
    received_chain: list[str] = field(default_factory=list)
    # Numele headerelor prezente, cu litere mici. Fingerprint-ul CyberReady se
    # uita dupa headere proprietare (X-CRPS, X-Virtual-MTA), iar newsletterele
    # legitime dupa List-Unsubscribe. Doar numele, nu si valorile.
    header_names: list[str] = field(default_factory=list)
    body_text: str = ""
    # HTML brut, pastrat DOAR pentru extragere de semnale (URL-uri, text ascuns).
    # Nu se randeaza niciodata in dashboard - sectiunea 4.2.
    body_html: str = ""
    urls: list[str] = field(default_factory=list)
    links: list[ParsedLink] = field(default_factory=list)
    attachments: list[ParsedAttachment] = field(default_factory=list)
    # True cand From/Subject vin din blocul de headere din CORPUL forward-ului,
    # nu din headerele mesajului. Atunci received_chain apartine wrapper-ului
    # (mesajul colegului), nu expeditorului din from_address - analizorul nu are
    # voie sa compare cele doua intre ele.
    headers_from_body: bool = False


URL_RE = re.compile(r"https?://[^\s<>\"'\]\)]+")

# Un header adevarat: nume, doua puncte, spatiu. Un URL nu se potriveste,
# pentru ca dupa "https" vine "://", nu ": ".
_HEADER_LINE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s")

# Forma singura nu ajunge: "Atentie: contul dvs..." are exact forma unui header.
# De aceea se cere si un nume cunoscut. Lista e mica si stabila - sunt headerele
# care scapa in corp la mailurile malformate si la forward-urile de client.
_KNOWN_HEADERS = frozenset(
    """
    arc-authentication-results arc-message-signature arc-seal authentication-results
    bcc cc content-disposition content-transfer-encoding content-type date
    delivered-to dkim-signature from in-reply-to list-id list-unsubscribe
    message-id mime-version precedence received references reply-to return-path
    sender subject to
    de-la trimis catre subiect data
    """.split()
)


def _is_header_line(line: str) -> bool:
    match = _HEADER_LINE_RE.match(line)
    if not match:
        return False
    name = match.group(1).lower()
    return name in _KNOWN_HEADERS or name.startswith("x-")


def _clean_body_text(raw_text: str) -> str:
    """Elimina headerele reziduale scapate in corp la mailurile malformate.

    Taie DOAR de la inceputul corpului si doar liniile care sunt headere
    cunoscute (plus continuarile lor pliate). Varianta veche stergea orice linie
    care contine ":", deci manca URL-urile de pe primul rand si avertismentele
    de forma "Atentie: ...".
    """
    lines = raw_text.splitlines()
    start = 0
    for i, line in enumerate(lines):
        if _is_header_line(line):
            start = i + 1
        elif start and line[:1] in (" ", "\t") and line.strip():
            start = i + 1  # continuare de header pliat
        else:
            break

    # randul gol care separa headerele de corp
    if start and start < len(lines) and not lines[start].strip():
        start += 1

    return "\n".join(lines[start:]).strip()


def _decode_part_payload(part: Message) -> str:
    """Decodeaza payload-ul unei parti, avand grija de Quoted-Printable si charset."""
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes) or not payload:
        return ""

    if str(part.get("Content-Transfer-Encoding", "")).lower() == "quoted-printable":
        with suppress(Exception):
            payload = quopri.decodestring(payload)

    charset = part.get_content_charset() or "utf-8"
    for enc in (charset, "utf-8", "iso-8859-1", "windows-1250"):
        try:
            return payload.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue

    return payload.decode("utf-8", errors="replace")


def _is_readable(text: str) -> bool:
    """Rezultatul unei decodari arata a text scris de om?

    Un base64 invalid se decodeaza cu succes in octeti aleatori, care apoi devin
    mojibake pe ecran. Mai bine lasam encoded-word-ul asa cum a venit: analistul
    vede ca headerul e stricat, in loc sa citeasca "iǬ���z�^m�".
    """
    if not text.strip():
        return False
    bad = sum(1 for ch in text if ch == "\ufffd" or (ord(ch) < 32 and ch not in "\t\n\r"))
    return bad / len(text) < 0.1


def _decode_b64(match: Match[str]) -> str:
    raw = re.sub(r"[^A-Za-z0-9+/=]", "", match.group(1).strip())
    raw += "=" * (-len(raw) % 4)
    try:
        text = base64.b64decode(raw).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return match.group(0)
    return text if _is_readable(text) else match.group(0)


def _decode_qp(match: Match[str]) -> str:
    """Un encoded-word de tip Q: "_" inseamna spatiu, "=XX" e un octet in hex.

    Cele doua transformari au sens DOAR aici, in interiorul unui =?utf-8?q?...?=.
    Aplicate pe text deja decodat stricau subiecte normale: 'Raport_final_2026'
    devenea 'Raport final 2026', iar 'Reducere 100%20 la produse' pierdea "%20".
    """
    qp = match.group(1).replace("_", " ")
    try:
        return urllib.parse.unquote(
            re.sub(r"=([0-9A-Fa-f]{2})", r"%\1", qp), encoding="utf-8", errors="replace"
        )
    except (ValueError, UnicodeError):
        return match.group(0)


_EW_B64_RE = re.compile(r"=\?[^?]+\?[bB]\?([^?]*)\?=")
_EW_QP_RE = re.compile(r"=\?[^?]+\?[qQ]\?([^?]*)\?=")


def decode_mime_header(header_value: str | None) -> str:
    """RFC 2047 pe headere. Biblioteca standard face treaba; noi doar curatam dupa.

    make_header() lipeste corect encoded-word-urile adiacente, inclusiv cand un
    cuvant a fost taiat in doua. Regex-urile de dupa prind doar ramasitele pe
    care stdlib nu le-a recunoscut (mailuri malformate, cazul 09).
    """
    if not header_value:
        return ""

    text = str(header_value)
    with suppress(Exception):
        text = str(make_header(decode_header(text)))

    if "=?" in text:
        text = _EW_B64_RE.sub(_decode_b64, text)
        text = _EW_QP_RE.sub(_decode_qp, text)

    return re.sub(r"\s+", " ", text).strip()


_FWD_HEADER_BLOCK_RE = re.compile(
    r"(?:From|De la)\s*:\s*(?P<from>.+?)\n"
    r"(?:Sent|Trimis|Date|Data)\s*:\s*.+?\n"
    r"(?:To|Către|Catre)\s*:\s*.+?\n"
    r"(?:Subject|Subiect)\s*:\s*(?P<subject>.+?)\n",
    re.IGNORECASE,
)


def extract_forwarded_headers(body_text: str) -> dict[str, str]:
    """Extrage blocul de headere inline dintr-un forward.

    Best-effort: e text scris de un client de mail, nu structurat ca un Message.
    Se cheama pe corpul BRUT, inainte de _clean_body_text - altfel curatarea a
    sters deja exact liniile pe care le cauta regex-ul.
    """
    match = _FWD_HEADER_BLOCK_RE.search(body_text)
    if not match:
        return {}
    return {
        "from": match.group("from").strip(),
        "subject": match.group("subject").strip(),
    }


def _archive_is_encrypted(payload: bytes) -> bool:
    """Bitul 0 din general purpose flag al headerului ZIP = continut criptat.

    Se citeste doar directorul central al arhivei. Arhiva NU se deschide, nu se
    extrage si nu se incearca nicio parola (sectiunea 4.1).
    """
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            return any(info.flag_bits & 0x1 for info in zf.infolist())
    except (zipfile.BadZipFile, OSError, ValueError):
        return False


def detect_report_kind(raw: bytes) -> ReportKind:
    msg = message_from_bytes(raw)
    has_image = False
    text_parts: list[str] = []

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
                text_parts.append(body.decode("utf-8", "replace"))

    # O raportare prin captura de ecran are aproape mereu si un rand de insotire
    # scris de coleg ("va trimit acest mesaj suspect") plus semnatura Outlook cu
    # logo. Conditia veche - imagine SI ZERO text - nu se implineste niciodata pe
    # o raportare reala, deci semnalul nu se producea. Ce separa cu adevarat
    # cazul e ca nu exista mesaj original de analizat: nici .eml atasat (tratat
    # mai sus), nici bloc de headere citat in corp. Ramane doar poza, pe care nu
    # o deschidem si nu o interpretam - deci decide un analist.
    if has_image and not extract_forwarded_headers("\n\n".join(text_parts)):
        return ReportKind.SCREENSHOT_ONLY

    subject = decode_mime_header(msg.get("Subject", "")).lower()
    if "fwd:" in subject or "fw:" in subject:
        return ReportKind.FORWARD_INLINE
    return ReportKind.UNKNOWN


def _inner_message(msg: Message) -> Message:
    """Mesajul .eml atasat, daca exista. Altfel mesajul primit."""
    for part in msg.walk():
        filename = (part.get_filename() or "").lower()
        if part.get_content_type() != "message/rfc822" and not filename.endswith(".eml"):
            continue

        payload = part.get_payload()
        if isinstance(payload, list) and payload and isinstance(payload[0], Message):
            return payload[0]
        if isinstance(payload, Message):
            return payload
        raw = part.get_payload(decode=True)
        if isinstance(raw, bytes) and raw:
            return message_from_bytes(raw)
    return msg


def _norm_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def parse_report(raw: bytes) -> ParsedEmail:
    kind = detect_report_kind(raw)
    outer = message_from_bytes(raw)
    msg = _inner_message(outer) if kind == ReportKind.ATTACHED_EML else outer

    subject = decode_mime_header(msg.get("Subject", ""))
    from_header = decode_mime_header(msg.get("From", ""))
    display_name, from_address = email.utils.parseaddr(from_header)

    reporter_display, reporter_address = email.utils.parseaddr(
        decode_mime_header(outer.get("From", ""))
    )

    sent_at: datetime | None = None
    with suppress(Exception):
        sent_at = email.utils.parsedate_to_datetime(str(outer.get("Date", "")))

    to_addresses = [
        addr.lower()
        for _, addr in email.utils.getaddresses(
            [decode_mime_header(v) for v in outer.get_all("To", []) + outer.get_all("Cc", [])]
        )
        if addr
    ]

    body_text_parts: list[str] = []
    html_parts: list[str] = []
    urls: set[str] = set()
    links: list[ParsedLink] = []
    attachments: list[ParsedAttachment] = []
    raw_text_parts: list[str] = []

    for part in msg.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))

        if "attachment" in disposition or part.get_filename():
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                filename = decode_mime_header(part.get_filename()) or "unnamed"
                attachments.append(
                    ParsedAttachment(
                        filename=filename,
                        sha256=hashlib.sha256(payload).hexdigest(),
                        mime_type=content_type,
                        size=len(payload),
                        encrypted_archive=_archive_is_encrypted(payload),
                    )
                )
            continue

        if content_type == "text/plain":
            text = _decode_part_payload(part)
            raw_text_parts.append(text)
            urls.update(URL_RE.findall(text))
            cleaned = _clean_body_text(text)
            if cleaned:
                body_text_parts.append(cleaned)

        elif content_type == "text/html":
            html = _decode_part_payload(part)
            if not html:
                continue
            html_parts.append(html)
            soup = BeautifulSoup(html, "html.parser")

            for a_tag in soup.find_all("a", href=True):
                if not isinstance(a_tag, Tag):
                    continue
                href = str(a_tag["href"])
                urls.add(href)
                links.append(ParsedLink(text=_norm_ws(a_tag.get_text()), href=href))

            urls.update(URL_RE.findall(html))

            # Textul din HTML se aduna MEREU, nu doar cand lipseste text/plain.
            # Altfel, la un multipart/alternative normal, partea HTML e sarita si
            # nici textul ascuns, nici cuvintele de marketing nu ajung la analizor.
            for element in soup(["script", "style"]):
                element.decompose()
            html_text = _clean_body_text(soup.get_text(separator="\n"))
            if html_text and _norm_ws(html_text) not in _norm_ws("\n".join(body_text_parts)):
                body_text_parts.append(html_text)
                raw_text_parts.append(html_text)

    full_body = "\n\n".join(body_text_parts).strip()

    # Headerele din corpul forward-ului se extrag din textul BRUT: _clean_body_text
    # taie exact liniile "From:/Sent:/To:/Subject:" pe care le cauta regex-ul.
    headers_from_body = False
    if kind == ReportKind.FORWARD_INLINE:
        fwd = extract_forwarded_headers("\n\n".join(raw_text_parts))
        if fwd.get("from"):
            fwd_display, fwd_addr = email.utils.parseaddr(fwd["from"])
            display_name = fwd_display or display_name
            from_address = fwd_addr or fwd["from"]
            headers_from_body = True
        if fwd.get("subject"):
            subject = fwd["subject"]

    return ParsedEmail(
        report_kind=kind,
        subject=subject,
        from_address=from_address or from_header,
        from_display_name=display_name.strip(),
        reporter_address=reporter_address,
        reporter_display_name=reporter_display.strip(),
        to_addresses=to_addresses,
        reply_to=decode_mime_header(msg.get("Reply-To", "")),
        return_path=decode_mime_header(msg.get("Return-Path", "")),
        auth_results=msg.get("Authentication-Results", ""),
        message_id=msg.get("Message-ID", ""),
        in_reply_to=msg.get("In-Reply-To", ""),
        references=msg.get("References", ""),
        sent_at=sent_at,
        received_chain=msg.get_all("Received", []),
        header_names=[str(name).lower() for name in msg],
        body_text=full_body,
        body_html="\n".join(html_parts),
        urls=sorted(urls),
        links=links,
        attachments=attachments,
        headers_from_body=headers_from_body,
    )
