from __future__ import annotations

import re
from triage.drafter.prompts import STATIC_TEMPLATES
from triage.verdicts import Analysis, Verdict


# TODO: nu o apeleaza nimeni. E singura poarta ceruta de 4.4.1 inainte de model,
# deci cand apare Ollama trebuie sa treaca tot pe aici.
def sanitize_for_model(text: str, max_chars: int = 2000) -> str:
    """Elimină tag-uri HTML, caractere speciale Unicode și trunchiază textul."""
    if not text:
        return ""

    # TODO: sterge doar tagurile, nu si continutul lor. "<script>ignore all previous
    # instructions</script>" ramane text curat si ajunge la model - exact atacul de
    # la 4.4. Parserul are deja BeautifulSoup: scoate script si style cu decompose(),
    # apoi get_text().
    # TODO: mananca si text normal. "a < b si c > d" devine "a d".
    # Elimina tag-urile HTML
    clean_text = re.sub(r"<[^>]*>", " ", text)
    # TODO: lipsesc FEFF, 2060 si 2066-2069, folosite si ele ca sa ascunda text de
    # om dar nu si de model.
    # TODO: 4.4.1 cere si scoaterea textului ascuns (culoare egala cu fundalul).
    # Elimina caracterele directionale Unicode si control zero-width
    clean_text = re.sub(r"[\u200B-\u200D\u200E\u200F\u202A-\u202E]", "", clean_text)
    # Normalizeaza spatiile albe
    clean_text = re.sub(r"\s+", " ", clean_text).strip()

    # TODO: 2000 e scris si in config/settings.yaml (llm.max_input_chars). Doua
    # locuri pentru acelasi numar, se vor desincroniza.
    # TODO: taie in mijlocul cuvantului si nu decodeaza entitatile HTML (&nbsp;).
    return clean_text[:max_chars]


# TODO: 6.4 cere ca input verdict + dovezi + nume raportor. analysis.evidence nu
# e folosit deloc, deci textul nu se poate adapta la ce a gasit analizorul.
# TODO: cand dovezile vor intra in draft, trec obligatoriu prin defang (4.2).
# TODO: lipseste tot 6.4: Ollama cu model 7-8B, prompt de sistem pe categorie
# (SYSTEM_PROMPTS din prompts.py exista deja si nu il foloseste nimeni),
# temperatura joasa si output scurt.
# TODO: lipseste si validarea ceruta de 4.4.3: daca modelul da ceva in afara
# formatului, arunci si cazi pe sablon. split_email din prompts.py e scris exact
# pentru asta si e folosit doar in scripts/eval_model.py.
# TODO: sablonul static e fallback-ul obligatoriu, nu calea principala. Bine ca
# a fost facut primul, dar deocamdata componenta nu acopera 6.4.
def build_draft(analysis: Analysis, reporter_name: str) -> str:
    """Generează draftul de răspuns.
    
    Dacă verdictul este NEEDS_REVIEW, returnează un string gol.
    Altfel, aplică șablonul static potrivit pe baza numelui raportorului.
    """
    # TODO: merge doar daca verdictul e chiar membru din enum. Venit ca string din
    # yaml ("SPAM"), comparatia e falsa si .name de mai jos crapa. Verdict e
    # StrEnum, deci foloseste Verdict(analysis.verdict).
    if analysis.verdict is Verdict.NEEDS_REVIEW:
        return ""

    # TODO: Outlook scrie numele ca "Popescu, Ion", deci prenume iese "Popescu,"
    # si mailul incepe cu "Buna ziua, Popescu,," - cu doua virgule, catre un coleg
    # real. O adresa de mail pusa ca nume trece intreaga.
    # TODO: numele nu e curatat deloc. Un enter sau un tag in display name strica
    # structura din trei parti pe care o verifica split_email.
    # Extrage prenumele (primul cuvant din nume)
    prenume = reporter_name.strip().split()[0] if reporter_name.strip() else "Coleg"

    verdict_key = analysis.verdict.name  # ex: "SIMULATION", "MALICIOUS", "LEGITIMATE"
    
    # TODO: mai jos intoarce tot "", ca la NEEDS_REVIEW. Apelantul nu poate face
    # diferenta intre "nu vrem draft" si "verdict necunoscut, deci bug". Mai bine raise.
    template = STATIC_TEMPLATES.get(verdict_key)
    if not template:
        return ""

    return template.format(prenume=prenume)