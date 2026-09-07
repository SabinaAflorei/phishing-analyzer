"""Detectie si eliminare de text ascuns prin stil CSS."""

from __future__ import annotations

import re

from bs4 import BeautifulSoup, Tag
from typing import Any

_HIDDEN_STYLE_PATTERNS = [
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?\b", re.IGNORECASE),
    re.compile(r"font-size\s*:\s*0?\.?[0-3]px", re.IGNORECASE),
]

_STYLE_COLOR_RE = re.compile(r"(?<!background-)color\s*:\s*([^;]+)", re.IGNORECASE)
_STYLE_BG_RE = re.compile(r"background(?:-color)?\s*:\s*([^;]+)", re.IGNORECASE)

_COLOR_ALIASES = {
    "white": "#ffffff", "#fff": "#ffffff",
    "black": "#000000", "#000": "#000000",
}


def _normalize_color(value: str) -> str:
    v = value.strip().lower().replace(" ", "")
    return _COLOR_ALIASES.get(v, v)


def _has_hidden_style(style: str) -> bool:
    if not style:
        return False
    if any(p.search(style) for p in _HIDDEN_STYLE_PATTERNS):
        return True
    color_match = _STYLE_COLOR_RE.search(style)
    bg_match = _STYLE_BG_RE.search(style)
    if color_match and bg_match:
        if _normalize_color(color_match.group(1)) == _normalize_color(bg_match.group(1)):
            return True
    return False


def contains_hidden_content(html: str) -> bool:
    """True daca exista cel putin un element cu text ascuns prin stil."""
    if not html:
        return False
    soup = BeautifulSoup(html, "html.parser")
    has_hidden = False
    for element in soup.find_all(style=True):
        raw_style = element.get("style", "")
        if isinstance(raw_style, list):
            style_value = "".join(raw_style)
        else:
            style_value = raw_style
        if _has_hidden_style(style_value):
            has_hidden = True
            element.decompose()
    return has_hidden


def strip_hidden_elements(html_or_text: str) -> str:
    """Elimina elementele cu text ascuns prin stil, apoi scoate tot HTML-ul.
    Sigur si pe text simplu (fara tag-uri) - trece neschimbat prin BeautifulSoup."""
    if not html_or_text:
        return ""
    soup = BeautifulSoup(html_or_text, "html.parser")
    for element in soup(["script", "style"]):
        element.decompose()
    for element in soup.find_all(style=True):
        if _has_hidden_style(element.get("style", "")):
            element.decompose()
    return soup.get_text(separator=" ")