"""Continut ostil, neutralizat.

Doua jumatati ale aceleiasi treburi: ce IESE din sistem (baza de date,
dashboard, log) e dezamorsat, iar ce INTRA la model e curatat de text ascuns.

Tiparele de text ascuns stau aici, nu in analizor si in drafter separat: acolo
erau doua copii care se potriveau pe lucruri usor diferite, deci se putea ajunge
la "nu am gasit text ascuns" intr-un loc si la o stergere in celalalt.
"""

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
    parsed = urlparse(url)

    # Fara schema, host si query nu e un URL cu token-uri, e text oarecare.
    # Trecerea lui prin urlencode il stalcea: un subiect de mail stricat, de
    # forma "=?utf-8?B?...?=", iesea percent-codat pe ecran.
    if not (parsed.scheme and parsed.netloc and parsed.query):
        return url

    params = [
        (key, "[STRIPPED]" if key.lower() in SENSITIVE_PARAMS else val)
        for key, val in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    # safe="[]" ca sa nu fie percent-codate parantezele din [STRIPPED].
    return urlunparse(parsed._replace(query=urlencode(params, safe="[]/")))


# ---------------------------------------------------------------------------
# Text ascuns: alb pe alb, 1px, display:none, opacitate zero, off-screen.
# Sectiunea 4.4 punctul 1 - se curata INAINTE ca textul sa ajunga la model,
# si se consemneaza ca dovada informativa de catre analizor.
# ---------------------------------------------------------------------------

HIDDEN_STYLE_RE = re.compile(
    r"(display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|font-size\s*:\s*0*[01](\.\d+)?\s*(px|pt)"
    r"|opacity\s*:\s*0(\.0+)?(\s|;|$)"
    r"|text-indent\s*:\s*-\d{3,}"
    r"|(^|[;\s])color\s*:\s*(#f{3}|#f{6}|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\)))",
    re.IGNORECASE,
)

# Invizibile si de control al directiei, inclusiv FEFF, 2060 si 2066-2069.
INVISIBLE_CHARS_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]")


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
