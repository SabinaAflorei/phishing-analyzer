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
import email.utils
import struct


class ReportKind(StrEnum):
    FORWARD_INLINE = "FORWARD_INLINE"
    ATTACHED_EML = "ATTACHED_EML"
    SCREENSHOT_ONLY = "SCREENSHOT_ONLY"  # -> NEEDS_REVIEW
    UNKNOWN = "UNKNOWN"
    SPAM = "SPAM"


@dataclass(slots=True)
class ParsedAttachment:
    filename: str
    sha256: str
    mime_type: str
    size: int
    is_encrypted_archive: bool = False

@dataclass(slots=True)
class ParsedLink:
    text: str
    href: str

_ZIP_LOCAL_HEADER_SIG = b"PK\x03\x04"
def _zip_is_encrypted(payload: bytes) -> bool:
    """Citeste doar bitul de criptare din local file header ZIP, fara sa
    deschida sau sa extraga arhiva - sectiunea 4.1, doar metadate."""
    if not payload.startswith(_ZIP_LOCAL_HEADER_SIG):
        return False
    try:
        # offset 6-7 in local file header = general purpose bit flag (2 bytes, little-endian)
        flags = struct.unpack("<H", payload[6:8])[0]
        return bool(flags & 0x0001)
    except (struct.error, IndexError):
        return False
    
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
    html_extracted_text: str = ""
    from_extracted_from_body: bool = False
    urls: list[str] = field(default_factory=list)
    suspicious_links: list[ParsedLink] = field(default_factory=list)
    attachments: list[ParsedAttachment] = field(default_factory=list)
    raw_html: str = ""   # HTML brut, NICIODATA afisat direct - doar pentru extragere URL-uri si detectie text ascuns 
    from_display_name: str = ""

_HEADER_LINE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s")

_URL_LIKE_TEXT_RE = re.compile(r"^(?:https?://)?[\w.-]+\.[a-z]{2,}(?:/\S*)?$", re.IGNORECASE)

def _looks_like_url(text: str) -> bool:
    return bool(_URL_LIKE_TEXT_RE.match(text.strip()))


def _hosts_match(link_text: str, href: str) -> bool:
    text_host = urllib.parse.urlparse(
        link_text if "://" in link_text else f"//{link_text}"
    ).netloc.lower() or link_text.lower().split("/")[0]
    real_host = urllib.parse.urlparse(href).netloc.lower()
    return text_host == real_host

def _clean_body_text(raw_text: str) -> str:
    """Elimină headerele reziduale scapate în corp din cauza e-mailurilor malformate."""
    lines = raw_text.splitlines()
    cleaned_lines = []
    in_headers = True

    for line in lines:
        if in_headers:
            if _HEADER_LINE_RE.match(line):
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
                    decoded_chunks.append(fragment.decode(charset, errors="replace"))
                except (UnicodeDecodeError, LookupError):
                    decoded_chunks.append(fragment.decode("iso-8859-1", errors="replace"))
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
            return urllib.parse.unquote(url_encoded, encoding="utf-8", errors="replace")
        except Exception:
            return match.group(0)

    text = re.sub(r"=\?[uU][tT][fF]-8\?[bB]\?([^?]*)\?=", decode_b64, text)
    text = re.sub(r"=\?[uU][tT][fF]-8\?[qQ]\?([^?]*)\?=", decode_qp, text)

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
    """Extrage blocul de headere inline dintr-un forward. Best-effort.

    Trebuie apelata pe textul BRUT, decodat dar necuratat de
    _clean_body_text - vezi apelul din parse_report, care foloseste
    full_raw_body, nu full_body.
    """
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
    from_display_name, _ = email.utils.parseaddr(from_address)
    from_display_name = decode_mime_header(from_display_name)
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    auth_results = msg.get("Authentication-Results", "")
    message_id = msg.get("Message-ID", "")
    in_reply_to = msg.get("In-Reply-To", "")
    references = msg.get("References", "")
    received_chain = msg.get_all("Received", [])

    raw_body_parts = []
    body_text_parts = []
    html_text_parts = []
    raw_html_parts = []
    suspicious_links = [] 
    urls = set()
    attachments = []
    url_pattern = re.compile(r"https?://[^\s<>\"']+")

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
                is_encrypted=(filename.lower().endswith((".zip", ".docx", ".xlsx", ".pptx")) 
                              and _zip_is_encrypted(payload)
                )
                attachments.append(
                    ParsedAttachment(
                        filename=filename,
                        sha256=sha256,
                        mime_type=content_type,
                        size=size,
                        is_encrypted_archive = is_encrypted,
                    )
                )
            continue

        if content_type == "text/plain":
            raw_text = _decode_part_payload(part)
            raw_body_parts.append(raw_text)
            text = _clean_body_text(raw_text)
            if text:
                body_text_parts.append(text)
                for match in url_pattern.findall(text):
                    urls.add(match)

        elif content_type == "text/html":
           html_content = _decode_part_payload(part)
           raw_html_parts.append(html_content)   # NOU: HTML brut, cu tot cu style=""

           soup = BeautifulSoup(html_content, "html.parser")
           for element in soup(["script", "style"]):
               element.decompose()
           extracted_text = _clean_body_text(soup.get_text(separator="\n"))
           if extracted_text:
             html_text_parts.append(extracted_text)
             if not body_text_parts:
              body_text_parts.append(extracted_text)

           for a_tag in soup.find_all("a", href=True):
             href = a_tag["href"]
             urls.add(href)
             link_text = a_tag.get_text(strip=True)
             if link_text and _looks_like_url(link_text) and not _hosts_match(link_text, href):
              suspicious_links.append(ParsedLink(text=link_text, href=href))

           for match in url_pattern.findall(html_content):
             urls.add(match)

    full_raw_body = "\n\n".join(raw_body_parts).strip()
    full_body = "\n\n".join(body_text_parts).strip()
    full_html_text = "\n\n".join(html_text_parts).strip()
    full_raw_html = "\n".join(raw_html_parts).strip()
    

    from_extracted_from_body = False
    if kind == ReportKind.FORWARD_INLINE:
        fwd_headers = extract_forwarded_headers(full_raw_body)
        if fwd_headers.get("from"):
            from_address = fwd_headers["from"]
            from_display_name, _ = email.utils.parseaddr(from_address)
            from_display_name = decode_mime_header(from_display_name)
            from_extracted_from_body = True
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
        html_extracted_text=full_html_text,
        from_extracted_from_body=from_extracted_from_body,
        urls=list(urls),
        attachments=attachments,
        suspicious_links=suspicious_links,
        raw_html=full_raw_html,
        from_display_name=from_display_name,
    )

