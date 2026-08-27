"""Extrage mesajul ORIGINAL, nu wrapper-ul colegului care a raportat."""

from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass, field
from email import message_from_bytes
from enum import StrEnum
from bs4 import BeautifulSoup  # type: ignore[import-untyped]

class ReportKind(StrEnum):
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
    subject = msg.get("Subject", "")
    if "fwd:" in subject.lower() or "fw:" in subject.lower():
        return ReportKind.FORWARD_INLINE
    return ReportKind.UNKNOWN


def parse_report(raw: bytes) -> ParsedEmail:
    msg = message_from_bytes(raw)
    kind = detect_report_kind(raw)
    # extragere headere
    subject = msg.get("Subject", "")
    from_address = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    auth_results = msg.get("Authentication-Results", "")
    received_chain = msg.get_all("Received", [])
    body_text_parts = []
    urls = set()
    attachments = []
    # Regex simplu pentru găsirea URL-urilor în text brut
    url_pattern = re.compile(r"https?://[^\s<>\"']+")
    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))
        # Procesare atașamente
        if "attachment" in disposition or part.get_filename():
            payload = part.get_payload(decode=True)
            if isinstance(payload,bytes):
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
        # Procesare corp text / HTML
        if content_type == "text/plain":
            payload = part.get_payload(decode=True)
            if isinstance(payload,bytes):
                text = payload.decode(errors="replace")
                body_text_parts.append(text)
                for match in url_pattern.findall(text):
                    urls.add(match)
        elif content_type == "text/html":
            payload = part.get_payload(decode=True)
            if isinstance(payload,bytes):
                html_content = payload.decode(errors="replace")
                soup = BeautifulSoup(html_content, "html.parser")
                # Extragem URL-urile din tag-urile <a>
                for a_tag in soup.find_all("a", href=True):
                    urls.add(a_tag["href"])
                    
    return ParsedEmail(
        report_kind=kind,
        subject=subject,
        from_address=from_address,
        reply_to=reply_to,
        return_path=return_path,
        auth_results=auth_results,
        received_chain=received_chain,
        body_text="\n".join(body_text_parts),
        urls=list(urls),
        attachments=attachments,
    )