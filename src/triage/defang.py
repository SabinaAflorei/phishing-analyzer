"""Defanging. Nimic nu iese din sistem (DB, dashboard, log) in forma clicabila."""

from __future__ import annotations

import re

_IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_SCHEME_RE = re.compile(r"\b(http|ftp)(s?)://", re.IGNORECASE)


def defang(value: str) -> str:
    """hxxps://exemplu[.]com/login ; 192[.]168[.]1[.]1"""
    out = _SCHEME_RE.sub(lambda m: f"{m.group(1)[0]}xx{m.group(1)[-1]}{m.group(2)}[://]", value)
    out = _IP_RE.sub(lambda m: "[.]".join(m.groups()), out)
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
