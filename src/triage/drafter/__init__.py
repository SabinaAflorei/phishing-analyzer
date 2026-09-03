from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from bs4 import BeautifulSoup, Tag

from triage.defang import defang
from triage.drafter.prompts import STATIC_TEMPLATES, SYSTEM_PROMPTS, split_email
from triage.verdicts import Analysis, Verdict

logger = logging.getLogger(__name__)

GENERIC_TERMS = {
    "scan",
    "serviciul",
    "service",
    "no-reply",
    "noreply",
    "support",
    "admin",
    "notification",
    "notifications",
    "info",
    "helpdesk",
    "ticketing",
    "desk",
    "system",
    "securitate",
}

# Text ascuns: alb pe alb, 1px, display:none, opacitate zero, off-screen.
# Sectiunea 4.4 punctul 1 - se curata INAINTE ca textul sa ajunga la model.
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
INVISIBLE_CHARS_RE = re.compile(r"[​-‍‎‏‪-‮﻿⁠⁦-⁩]")

DEFAULT_MAX_INPUT_CHARS = 2000


def _strip_hidden_elements(soup: BeautifulSoup) -> None:
    """Scoate elementele facute invizibile prin stil.

    Astea sunt exact vehiculul din cazul 08: instructiuni catre model, ascunse
    de ochiul colegului dar perfect vizibile pentru orice parser de text. Se
    sterge tot subarborele, nu doar tag-ul, altfel continutul ramane.
    """
    for element in soup.find_all(style=True):
        if isinstance(element, Tag) and HIDDEN_STYLE_RE.search(str(element.get("style", ""))):
            element.decompose()

    for element in soup.find_all(attrs={"hidden": True}):
        if isinstance(element, Tag):
            element.decompose()


def sanitize_for_model(text: str, max_chars: int | None = None) -> str:
    """Curata textul inainte sa ajunga la model (sectiunea 4.4).

    1. scoate script/style cu tot cu continut
    2. scoate elementele ascunse prin stil (alb pe alb, 1px, display:none)
    3. scoate caracterele Unicode invizibile si de control al directiei
    4. normalizeaza spatiile
    5. trunchiaza la `max_chars`, pe limita de cuvant
    """
    if not text:
        return ""

    limit = DEFAULT_MAX_INPUT_CHARS if max_chars is None else max_chars

    soup = BeautifulSoup(text, "html.parser")
    for element in soup(["script", "style"]):
        element.decompose()
    _strip_hidden_elements(soup)

    clean_text = soup.get_text(separator=" ")
    clean_text = INVISIBLE_CHARS_RE.sub("", clean_text)
    clean_text = re.sub(r"\s+", " ", clean_text).strip()

    if len(clean_text) > limit:
        truncated = clean_text[:limit]
        last_space = truncated.rfind(" ")
        clean_text = truncated[:last_space] if last_space > 0 else truncated

    return clean_text


def extract_first_name(from_header: str) -> str | None:
    """Primul nume valid. None pentru numele generice de sistem."""
    if not from_header or from_header == "Necunoscut":
        return None

    display_name = from_header.split("<")[0].replace('"', "").strip()
    if not display_name and "@" in from_header:
        display_name = from_header.split("@")[0].replace("<", "").strip()
    if not display_name:
        return None

    if "," in display_name:
        parts = display_name.split(",")
        if len(parts) > 1 and parts[1].strip():
            display_name = parts[1].strip()

    first_word = display_name.split()[0] if display_name else ""
    first_word_clean = re.sub(r"[^a-zA-ZăâîșțĂÂÎȘȚ-]", "", first_word)

    if (
        not first_word_clean
        or first_word_clean.lower() in GENERIC_TERMS
        or len(first_word_clean) < 2
    ):
        return None

    return first_word_clean.capitalize()


def _format_evidence_for_prompt(analysis: Analysis, max_chars: int) -> str:
    """Dovezile, curatate si defangate, gata de trimis modelului."""
    if not analysis.evidence:
        return "Nu există detalii suplimentare specifice."

    lines = []
    for ev in analysis.evidence:
        clean_detail = sanitize_for_model(ev.detail, max_chars) if ev.detail else ""
        clean_desc = sanitize_for_model(ev.description, max_chars)
        detail_str = f" ({defang(clean_detail)})" if clean_detail else ""
        lines.append(f"- [{ev.code}] {defang(clean_desc)}{detail_str}")

    return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class Draft:
    text: str
    source: str  # "llm" | "template" | "none"


def generate_draft(
    analysis: Analysis,
    reporter_name: str,
    llm_client: Any = None,
    max_input_chars: int | None = None,
) -> Draft:
    """Draftul, plus de unde a venit.

    Provenienta conteaza: fara ea nu poti spune, la o saptamana distanta, daca
    rata de acceptare masoara modelul sau template-ul static.
    """
    try:
        verdict_obj = Verdict(analysis.verdict)
    except ValueError:
        raise ValueError(f"Verdict necunoscut sau invalid: {analysis.verdict}") from None

    if verdict_obj == Verdict.NEEDS_REVIEW:
        # Nu se trimite nimic automat cand nici sistemul nu stie ce e mailul.
        return Draft(text="", source="none")

    limit = DEFAULT_MAX_INPUT_CHARS if max_input_chars is None else max_input_chars
    prenume = extract_first_name(reporter_name)
    verdict_key = verdict_obj.name
    prenume_str = f", {prenume}" if prenume else ""

    if llm_client is not None:
        text = _try_llm(llm_client, verdict_key, prenume, analysis, limit)
        if text:
            return Draft(text=text, source="llm")

    template = STATIC_TEMPLATES.get(verdict_key)
    if not template:
        raise ValueError(f"Nu există șablon static pentru verdictul: {verdict_key}")
    return Draft(text=template.format(prenume=prenume_str), source="template")


def _try_llm(
    llm_client: Any, verdict_key: str, prenume: str | None, analysis: Analysis, limit: int
) -> str:
    """Incearca modelul. Orice esec inseamna template static, nu exceptie.

    Validarea output-ului (sectiunea 4.4 punctul 3) se face cu split_email: daca
    lipseste salutul, corpul sau incheierea, textul e aruncat. Modelul poate
    scrie orice; noi acceptam doar forma ceruta.
    """
    system_prompt = SYSTEM_PROMPTS.get(verdict_key)
    if not system_prompt:
        return ""

    try:
        evidence_text = _format_evidence_for_prompt(analysis, limit)
        prompt_prenume = (
            f"Prenume coleg: {prenume}\n"
            if prenume
            else "Prenume coleg: Necunoscut (Folosește doar 'Bună ziua,')\n"
        )
        response = llm_client.generate(
            system_prompt=system_prompt,
            prompt=f"{prompt_prenume}Dovezi analiză:\n{evidence_text}",
            temperature=0.1,
        )
    except Exception as err:
        logger.warning("Modelul nu a raspuns (%s). Se foloseste template-ul static.", err)
        return ""

    if not response:
        return ""

    text = str(response).strip()
    greeting, body, closing = split_email(text)
    if not (greeting and body and closing):
        logger.warning("Output invalid de la model (structura). Se foloseste template-ul static.")
        return ""
    return text


def build_draft(analysis: Analysis, reporter_name: str, llm_client: Any = None) -> str:
    """Doar textul. Pentru apelantii carora nu le pasa de provenienta."""
    return generate_draft(analysis, reporter_name, llm_client).text
