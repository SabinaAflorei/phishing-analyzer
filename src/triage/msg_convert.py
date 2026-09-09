"""Conversie Outlook .msg (OLE) -> .eml (RFC822). Offline, fara retea.

De ce exista ca modul si nu doar ca script: acelasi cod e folosit in doua locuri
- `scripts/msg_to_eml.py`, la pregatirea corpusului, si dashboard-ul, cand cineva
arunca un .msg in pagina. Doua implementari ale aceleiasi conversii ar diverge, iar
diferenta s-ar vedea abia in verdicte.

Ce se pastreaza, in ordinea importantei pentru analizor:

1. Headerele de transport originale (PR_TRANSPORT_MESSAGE_HEADERS, 0x007D).
   Acolo stau Authentication-Results, lantul Received, Return-Path si
   DKIM-Signature. Fara ele analiza de autentificare nu are ce citi.
2. Corpul text si corpul HTML, ca multipart/alternative.
3. Imaginile inline (cu Content-ID), ca multipart/related.
4. Mesajele atasate: un .msg incorporat devine un part message/rfc822, convertit
   recursiv - asa functioneaza cazul 02, unde mesajul original e atasament.
5. Restul atasamentelor, cu numele si tipul lor. Continutul NU se deschide, nu se
   executa si nu se inspecteaza - se copiaza octet cu octet.

Determinism: boundary-urile vin dintr-un contor, nu din random, deci aceeasi
intrare da acelasi octet de iesire. Poti reface corpusul oricand, diff-ul ramane gol.

`extract_msg` se importa LENES, in interiorul functiei. E o unealta de pregatire a
corpusului (trage oletools, cryptography si inca vreo zece pachete), nu o
dependinta de runtime - vezi requirements-corpus.txt. Sistemul porneste si merge
fara ea; doar conversia unui .msg cere sa fie instalata, si atunci spune clar asta.

Nu atinge reteaua. Nu rezolva DNS. Nu descarca nimic.
"""

from __future__ import annotations

import re
from email.message import EmailMessage, Message
from email.parser import HeaderParser
from email.policy import SMTP, Policy
from pathlib import Path
from typing import Any, cast

# Semnatura OLE2/CFB, cu care incepe orice fisier .msg. Detectia se face pe
# CONTINUT, nu pe extensie: un fisier salvat din Outlook ajunge des redenumit,
# iar extensia e oricum alegerea celui care trimite, deci nu o dovada.
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class MsgConversionUnavailable(RuntimeError):
    """extract-msg nu e instalat, deci .msg-urile nu pot fi convertite aici."""


def looks_like_msg(raw: bytes) -> bool:
    """Fisier Outlook .msg? Dupa semnatura OLE, nu dupa numele fisierului."""
    return raw[:8] == OLE_MAGIC


# Un header RFC822: nume de camp, doua puncte, valoare. `From ` fara doua puncte
# e prima linie a unui mbox, tot un mesaj valid pentru noi.
_HEADER_RE = re.compile(rb"^[A-Za-z][A-Za-z0-9-]{0,60}:")


def looks_like_rfc822(raw: bytes) -> bool:
    """Pare un .eml? Prima linie ne-goala trebuie sa fie un header.

    Nu valideaza mesajul - doar deosebeste un e-mail de un PDF sau o poza aruncata
    din greseala in pagina. Un mesaj STRICAT trebuie sa treaca de aici: sectiunea
    8.3 cere ca un mail malformat sa fie analizat, nu respins.
    """
    for line in raw[:8192].splitlines():
        if not line.strip():
            continue
        return bool(_HEADER_RE.match(line)) or line.startswith(b"From ")
    return False


def detect_format(raw: bytes) -> str:
    """`msg`, `eml` sau `unknown`, dupa continut."""
    if looks_like_msg(raw):
        return "msg"
    if looks_like_rfc822(raw):
        return "eml"
    return "unknown"


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
    # typeshed tipeaza HeaderParser pe Policy[Message[str, str]], iar SMTP e
    # EmailPolicy[EmailMessage]. La rulare e exact combinatia corecta - citim
    # doar headere - dar tipul nu se poate exprima fara cast.
    header_policy = cast("Policy[Message[str, str]]", SMTP)
    parsed = HeaderParser(policy=header_policy).parsestr(raw, headersonly=True)
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


def msg_bytes_to_eml(raw: bytes) -> bytes:
    """Octetii unui .msg -> octetii unui .eml. Ridica MsgConversionUnavailable."""
    try:
        import extract_msg
    except ImportError as err:  # pragma: no cover - depinde de mediul de instalare
        raise MsgConversionUnavailable(
            "Conversia .msg cere extract-msg: pip install -r requirements-corpus.txt"
        ) from err

    # extract-msg nu are adnotari, deci constructorul apare ca apel netipat
    # intr-un modul strict. Ignorarea e strict pe linia asta.
    msg = extract_msg.Message(raw)  # type: ignore[no-untyped-call]
    try:
        return bytes(convert(msg).as_bytes())
    finally:
        msg.close()
