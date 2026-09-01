#!/usr/bin/env python3
"""Converteste raportarile Outlook .msg in .eml, o singura data, la pregatirea corpusului.

De ce exista: mesajele exportate din Outlook sunt fisiere OLE (.msg), iar
pipeline-ul lucreaza exclusiv cu RFC822 (.eml). Conversia se face aici, offline,
inainte ca fisierele sa intre in corpus - nu in parser. Parser-ul vede doar .eml.

Ce se pastreaza, in ordinea importantei pentru analizor:

1. Headerele de transport originale (PR_TRANSPORT_MESSAGE_HEADERS, 0x007D).
   Acolo stau Authentication-Results, lantul Received, Return-Path si
   DKIM-Signature. Fara ele analiza de autentificare nu are ce citi.
2. Corpul text si corpul HTML, ca multipart/alternative.
3. Imaginile inline (cu Content-ID), ca multipart/related.
4. Mesajele atasate. Un .msg incorporat devine un part message/rfc822, convertit
   recursiv - asa functioneaza cazul 02, unde mesajul original e atasament.
5. Restul atasamentelor, cu numele si tipul lor. Continutul nu se deschide,
   nu se executa si nu se inspecteaza - se copiaza octet cu octet.

Determinism: boundary-urile sunt generate dintr-un contor, nu aleator, deci
aceeasi intrare produce mereu acelasi octet de iesire. Poti reface corpusul
oricand si diff-ul ramane gol.

Nu atinge reteaua. Nu rezolva DNS. Nu descarca nimic.

Dependinta (doar pentru pregatirea corpusului, nu pentru runtime):
    pip install extract-msg

Utilizare:
    python3 scripts/msg_to_eml.py corpus/eml/1.msg -o corpus/eml/01_cyberready_forward.eml
    python3 scripts/msg_to_eml.py corpus/eml/*.msg --outdir out/
    python3 scripts/msg_to_eml.py corpus/eml/1.msg --stdout | head -40
"""

from __future__ import annotations

import argparse
import sys
from email.message import EmailMessage
from email.parser import HeaderParser
from email.policy import SMTP
from pathlib import Path
from triage.storage import save_secure_file
from typing import Any


try:
    import extract_msg
except ImportError:  # pragma: no cover
    sys.exit("Lipseste extract-msg. Ruleaza: pip install extract-msg")

# Headerele wrapper-ului TNEF descriu winmail.dat, nu mesajul pe care il
# reconstruim. Daca le-am pastra, ar contrazice structura MIME pe care o scriem.
_DROP_HEADERS = {
    "content-type",
    "content-transfer-encoding",
    "content-disposition",
    "mime-version",
    "x-ms-tnef-correlator",
}

_MAX_HEADER_BYTES = 200_000


class _Boundaries:
    """Boundary-uri stabile: acelasi .msg -> acelasi .eml, byte cu byte."""

    def __init__(self) -> None:
        self._n = 0

    def next(self) -> str:
        self._n += 1
        return f"===============msg2eml{self._n:04d}=="


def _transport_headers(msg: Any) -> list[tuple[str, str]]:
    """Headerele originale de internet, asa cum le-a vazut serverul de mail."""
    raw = msg.getStringStream("__substg1.0_007D") or ""
    if not raw or len(raw) > _MAX_HEADER_BYTES:
        return []
    parsed = HeaderParser(policy=SMTP).parsestr(raw, headersonly=True)
    return [(k, str(v)) for k, v in parsed.items() if k.lower() not in _DROP_HEADERS]


def _fallback_headers(msg: Any) -> list[tuple[str, str]]:
    """Cand .msg nu are headere de transport (mesaj compus local, niciodata trimis)."""
    out: list[tuple[str, str]] = []
    for name, value in (
        ("From", msg.sender),
        ("To", msg.to),
        ("Cc", msg.cc),
        ("Subject", msg.subject),
        ("Message-ID", msg.messageId),
    ):
        if value:
            out.append((name, str(value)))
    if msg.date:
        out.append(("Date", msg.date.strftime("%a, %d %b %Y %H:%M:%S %z")))
    return out


def _html_body(msg: Any) -> str:
    """Corpul HTML se extrage DOAR pentru URL-uri. Nu se randeaza niciodata."""
    raw = msg.htmlBody
    if not raw:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def _is_embedded_message(att: Any) -> bool:
    return type(att).__name__ == "EmbeddedMsgAttachment"


def _attachment_bytes(att: Any) -> bytes:
    data = att.data
    if isinstance(data, bytes | bytearray):
        return bytes(data)
    return b""


def _split_mimetype(att: Any, filename: str) -> tuple[str, str]:
    mime = getattr(att, "mimetype", None)
    if isinstance(mime, str) and "/" in mime:
        maintype, _, subtype = mime.partition("/")
        return maintype, subtype
    ext = Path(filename).suffix.lower().lstrip(".")
    known = {
        "png": ("image", "png"),
        "jpg": ("image", "jpeg"),
        "jpeg": ("image", "jpeg"),
        "gif": ("image", "gif"),
        "pdf": ("application", "pdf"),
        "txt": ("text", "plain"),
    }
    return known.get(ext, ("application", "octet-stream"))


def _build_body(msg: Any, bounds: _Boundaries) -> EmailMessage:
    """text/plain (+ text/html) (+ imagini inline) -> un singur part."""
    text = msg.body or ""
    html = _html_body(msg)

    body = EmailMessage(policy=SMTP)
    body.set_content(text, subtype="plain", charset="utf-8")
    if html:
        body.add_alternative(html, subtype="html", charset="utf-8")
        body.set_boundary(bounds.next())

    inline = [
        a
        for a in msg.attachments
        if not _is_embedded_message(a) and a.cid and getattr(a, "hidden", False)
    ]
    if not inline:
        return body

    related = EmailMessage(policy=SMTP)
    related["Content-Type"] = "multipart/related"
    related.set_boundary(bounds.next())
    related.attach(body)
    for att in inline:
        filename = att.getFilename() or "inline"
        maintype, subtype = _split_mimetype(att, filename)
        part = EmailMessage(policy=SMTP)
        part.set_content(
            _attachment_bytes(att),
            maintype=maintype,
            subtype=subtype,
            filename=filename,
            disposition="inline",
            cid=f"<{att.cid}>",
        )
        related.attach(part)
    return related


def convert(msg: Any, bounds: _Boundaries | None = None) -> EmailMessage:
    """Un .msg (sau un mesaj incorporat) -> un EmailMessage complet."""
    bounds = bounds or _Boundaries()

    headers = _transport_headers(msg) or _fallback_headers(msg)
    body = _build_body(msg, bounds)

    attachments = [
        a
        for a in msg.attachments
        if _is_embedded_message(a) or not (a.cid and getattr(a, "hidden", False))
    ]

    if not attachments:
        out = body
    else:
        out = EmailMessage(policy=SMTP)
        out["Content-Type"] = "multipart/mixed"
        out.set_boundary(bounds.next())
        out.attach(body)
        for att in attachments:
            filename = att.getFilename() or "atasament"
            if _is_embedded_message(att):
                inner = convert(att.data, bounds)
                part = EmailMessage(policy=SMTP)
                part.set_content(inner, subtype="rfc822")
                part.add_header(
                    "Content-Disposition", "attachment", filename=f"{Path(filename).stem}.eml"
                )
                out.attach(part)
                continue
            maintype, subtype = _split_mimetype(att, filename)
            part = EmailMessage(policy=SMTP)
            part.set_content(
                _attachment_bytes(att),
                maintype=maintype,
                subtype=subtype,
                filename=filename,
                disposition="attachment",
            )
            out.attach(part)

    for key, value in headers:
        del out[key]
        out[key] = value
    if "MIME-Version" not in out:
        out["MIME-Version"] = "1.0"
    return out


def convert_file(path: Path) -> bytes:
    msg = extract_msg.Message(str(path))
    try:
        return convert(msg).as_bytes()
    finally:
        msg.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("inputs", nargs="+", type=Path, help="fisiere .msg")
    ap.add_argument("-o", "--output", type=Path, help="fisier .eml de iesire (o singura intrare)")
    ap.add_argument("--outdir", type=Path, help="director de iesire, pastreaza numele")
    ap.add_argument("--stdout", action="store_true", help="scrie la stdout")
    args = ap.parse_args()

    if args.output and len(args.inputs) > 1:
        ap.error("--output merge doar cu o singura intrare; foloseste --outdir")

    for src in args.inputs:
        raw = convert_file(src)
        if args.stdout:
            sys.stdout.buffer.write(raw)
            continue
        if args.output:
            dst = args.output
        elif args.outdir:
            dst = args.outdir / (src.stem + ".eml")
        else:
            dst = src.with_suffix(".eml")
            
        # Salvare securizată cu permisiuni 0o600
        save_secure_file(dst, raw)
        print(f"{src} -> {dst}  ({len(raw)} octeti)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
