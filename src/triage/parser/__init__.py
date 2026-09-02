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
    auth_results: str = ""
    received_chain: list[str] = field(default_factory=list)
    body_text: str = ""
    urls: list[str] = field(default_factory=list)
    attachments: list[ParsedAttachment] = field(default_factory=list)

def _clean_body_text(raw_text: str) -> str:
    """Elimină headerele reziduale scapate în corp din cauza e-mailurilor malformate."""
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

    try:
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
    except Exception:
        pass  # noqa : S110
    
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

    text = text.replace("_", " ")
    text = re.sub(r"=([0-9A-Fa-f]{2})", r"%\1", text)
    try:
        text = urllib.parse.unquote(text, encoding="utf-8", errors="replace")
    except Exception:
        pass # noqa : S110, SIM105

    text = re.sub(r"\s+=\s+", " ", text)
    return re.sub(r"\s+", " ", text).strip()

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
    received_chain = msg.get_all("Received", [])

    body_text_parts = []
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

    return ParsedEmail(
        report_kind=kind,
        subject=subject,
        from_address=from_address,
        reply_to=reply_to,
        return_path=return_path,
        auth_results=auth_results,
        received_chain=received_chain,
        body_text=full_body,
        urls=list(urls),
        attachments=attachments,
    )