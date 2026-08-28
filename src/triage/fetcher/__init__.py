"""IMAP read-only + sursa statica de .eml. Nu sterge si nu muta mesaje."""

from __future__ import annotations

from pathlib import Path


# TODO: 3 zice ca fetcher, parser, analyzer si drafter comunica printr-o baza de
# date, tocmai ca un bug intr-unul sa nu piarda mail-uri. Aici se intoarce o
# lista direct catre apelant si nu exista nicio DB in proiect.
def fetch_from_corpus(corpus_dir: Path) -> list[Path]:
    """Sursa offline pentru dezvoltare si teste.
    
    Cauta toate fisierele de mail (.msg / .eml) din directorul corpus.
    """
    # TODO: director lipsa si director gol dau acelasi rezultat. O cale gresita in
    # config arata exact ca "nu a venit nicio raportare". Vezi 6.1: erorile se
    # trateaza vizibil, nu in tacere.
    if not corpus_dir.exists() or not corpus_dir.is_dir():
        return []

    # TODO: .msg nu are ce cauta aici. E fisier OLE, nu RFC822, iar parserul il
    # citeste ca mail gol: fara headere, fara URL-uri, deci verdict gresit fara
    # nicio eroare. Conversia se face inainte, cu scripts/msg_to_eml.py.
    # TODO: glob e case-sensitive pe Linux, deci .EML exportat din Outlook se pierde.
    # Cauta fisierele .msg si .eml din corpus si le sorteaza
    # TODO: list() in sorted() nu face nimic, sorted accepta orice iterabil.
    files = sorted(list(corpus_dir.glob("*.msg")) + list(corpus_dir.glob("*.eml")))
    return files


def fetch_from_imap() -> list[Path]:
    """Poll read-only. Marcheaza procesatele in DB, nu le sterge. Idempotent la restart."""
    # TODO: aici lipseste tot 6.1: poll la interval din settings (5 min), salvarea
    # .eml brut pe disc cu permisiuni 600, evidenta mesajelor procesate in DB ca
    # sa nu se dubleze la repornire, si retry cand mailbox-ul nu raspunde.
    # Stub offline pentru IMAP
    return []