from __future__ import annotations

import logging
import re
from typing import Any

from bs4 import BeautifulSoup

from triage.defang import defang
from triage.drafter.prompts import STATIC_TEMPLATES, SYSTEM_PROMPTS, split_email
from triage.verdicts import Analysis, Verdict

logger = logging.getLogger(__name__)


def sanitize_for_model(text: str, max_chars: int = 2000) -> str:
    """Elimină tag-uri HTML periculoase (script/style cu conținut), caractere Unicode invizibile
    și trunchiază textul la lungimea maximă admisă fără a tăia cuvinte.
    """
    if not text:
        return ""

    # 1. Eliminare taguri <script> și <style> si cu continutul lor (previne Prompt Injection)
    soup = BeautifulSoup(text, "html.parser")
    for element in soup(["script", "style"]):
        element.decompose()

    clean_text = soup.get_text(separator=" ")

    # 2. Eliminare caractere invizibile / directionale Unicode (incluzând FEFF, 2060, 2066-2069)
    invisible_chars_pattern = r"[\u200B-\u200D\u200E\u200F\u202A-\u202E\uFEFF\u2060\u2066-\u2069]"
    clean_text = re.sub(invisible_chars_pattern, "", clean_text)

    # 3. Normalizare spatii albe
    clean_text = re.sub(r"\s+", " ", clean_text).strip()

    # 4. Trunchiere pe limita de cuvânt
    if len(clean_text) > max_chars:
        truncated = clean_text[:max_chars]
        last_space = truncated.rfind(" ")
        if last_space > 0:
            clean_text = truncated[:last_space]
        else:
            clean_text = truncated

    return clean_text


def extract_first_name(reporter_name: str) -> str:
    """Extrage și curăță prenumele din numele raportorului.
    Gestionează formatele 'Popescu, Ion', adrese de e-mail sau nume simple.
    """
    if not reporter_name:
        return "Coleg"

    # Sanitizare newline-uri sau taguri
    cleaned = re.sub(r"[<>\"\r\n]", "", reporter_name).strip()

    if "@" in cleaned:
        cleaned = cleaned.split("@")[0].replace(".", " ")

    # Formatul "Nume, Prenume"
    if "," in cleaned:
        parts = [p.strip() for p in cleaned.split(",") if p.strip()]
        if len(parts) >= 2:
            return parts[1].split()[0].capitalize()
        cleaned = parts[0]

    parts = cleaned.split()
    if parts:
        return parts[0].capitalize()

    return "Coleg"


def _format_evidence_for_prompt(analysis: Analysis) -> str:
    """Formatează și aplică defang pe dovezile din analiză pentru a le trimite sigur modelului LLM."""
    if not analysis.evidence:
        return "Nu există detalii suplimentare specifice."

    formatted_lines = []
    for ev in analysis.evidence:
        detail_str = f" ({defang(ev.detail)})" if ev.detail else ""
        desc_defanged = defang(ev.description)
        formatted_lines.append(f"- [{ev.code}] {desc_defanged}{detail_str}")

    return "\n".join(formatted_lines)


def build_draft(analysis: Analysis, reporter_name: str, llm_client: Any = None) -> str:
    """Generează draftul de răspuns.

    Dacă verdictul este NEEDS_REVIEW, returnează un string gol.
    Trage din Ollama (dacă este furnizat/disponibil) și validează outputul cu split_email.
    Fallback automat pe șabloanele statice dacă modelul eșuează sau dă un output invalid.
    """
    # Asigurare compatibilitate (daca verdictul vine ca string)
    try:
        verdict_obj = Verdict(analysis.verdict)
    except ValueError:
        raise ValueError(f"Verdict necunoscut sau invalid: {analysis.verdict}")

    if verdict_obj == Verdict.NEEDS_REVIEW:
        return ""

    prenume = extract_first_name(reporter_name)
    verdict_key = verdict_obj.name

    # 1. Incercare de generare dinamica via LLM / Ollama
    if llm_client is not None:
        try:
            system_prompt = SYSTEM_PROMPTS.get(verdict_key)
            if system_prompt:
                evidence_text = _format_evidence_for_prompt(analysis)
                user_message = (
                    f"Prenume coleg: {prenume}\n"
                    f"Dovezi analiză:\n{evidence_text}"
                )

                # Generare text
                response_text = llm_client.generate(
                    system_prompt=system_prompt,
                    prompt=user_message,
                    temperature=0.1,
                )

                if response_text:
                    greeting, body, closing = split_email(str(response_text))
                    if greeting and body and closing:
                        return str(response_text).strip()
                    logger.warning(
                        "Răspunsul LLM nu a trecut de validarea split_email. Se folosește fallback static."
                    )
        except Exception as err:
            logger.error("Eroare la generarea draftului cu LLM: %s. Se folosește fallback-ul.", err)

    # 2. Fallback static 
    template = STATIC_TEMPLATES.get(verdict_key)
    if not template:
        raise ValueError(f"Nu există șablon static pentru verdictul: {verdict_key}")

    return template.format(prenume=prenume)