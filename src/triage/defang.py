"""Defanging. Nimic nu iese din sistem (DB, dashboard, log) in forma clicabila."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_SCHEME_RE = re.compile(r"\b(http|ftp)(s?)://", re.IGNORECASE)
_URL_RE = re.compile(r"\b(?:https?|ftps?)://[^\s<>\"\']+", re.IGNORECASE)

SENSITIVE_PARAMS = {
    "token",
    "auth",
    "access_token",
    "id_token",
    "secret",
    "api_key",
    "key",
    "sig",
    "signature",
    "pass",
    "password",
    "ticket",
}


def strip_url_tokens(url: str) -> str:
    """Înlocuiește valorile parametrilor sensibili din query string cu [STRIPPED]."""
    if not url:
        return ""

    try:
        parsed = urlparse(url)
        # Fara schema si host nu e un URL, e text oarecare. Trecerea lui prin
        # urlencode il stalcea: un subiect de mail stricat, de forma
        # "=?utf-8?B?...?=", iesea percent-codat pe ecran.
        if not parsed.scheme or not parsed.netloc:
            return url
        if not parsed.query:
            return url

        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        stripped_params = []

        for key, val in query_params:
            if key.lower() in SENSITIVE_PARAMS:
                stripped_params.append((key, "[STRIPPED]"))
            else:
                stripped_params.append((key, val))

        # Adaugam safe="[]" pentru a preveni percent-encoding pe paranteze
        new_query = urlencode(stripped_params, safe="[]/")
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)
    except Exception:
        return re.sub(
            r"((?:token|auth|access_token|secret|key|sig)=)[^&]+",
            r"\1[STRIPPED]",
            url,
            flags=re.IGNORECASE,
        )


def defang(value: str) -> str:
    """hxxps://exemplu[.]com/login ; 192[.]168[.]1[.]1"""
    if not value:
        return ""

    # Curatarea de token-uri se aplica pe FIECARE URL din text, nu pe textul
    # intreg: `value` e de obicei un subiect, un corp de mail sau un header,
    # nu un URL singur.
    out = _URL_RE.sub(lambda m: strip_url_tokens(m.group(0)), value)

    # Defanging pe scheme (http:// -> hxxp[://])
    out = _SCHEME_RE.sub(lambda m: f"{m.group(1)[0]}xx{m.group(1)[-1]}{m.group(2)}[://]", out)

    # Defanging pe IP-uri
    out = _IP_RE.sub(lambda m: "[.]".join(m.groups()), out)

    # Defanging pe domenii/puncte
    out = re.sub(r"\.(?=[A-Za-z0-9-]{1,63}\b)", "[.]", out)

    return out


def refang(value: str) -> str:
    """Doar pentru teste. NU se foloseste in productie."""
    return (
        value.replace("[://]", "://")
        .replace("[.]", ".")
        .replace("hxxp", "http")
        .replace("fxxp", "ftp")
    )