"""Scriere sigura de fisiere pe disc: nume curatat, permisiuni 0600.

Numele vechi era "storage", ceea ce il confunda cu stocarea feedback-ului
din dashboard. Aceea a ajuns in db.py, iar fisierul asta s-a redenumit dupa
ce face: scriere sigura de fisiere.
"""

import os
from pathlib import Path
import re


def sanitize_filename(filename: str) -> str:
    """Curăță numele fișierului de secvențe de path traversal și caractere speciale."""
    clean_name = Path(filename).name
    clean_name = re.sub(r"[^\w\.-]", "_", clean_name)
    return clean_name or "unnamed_attachment"


def save_secure_file(file_path: Path | str, content: bytes | str) -> None:
    """Salvează un fișier pe disc setând permisiunile la 0o600 (rw-------)."""
    target = Path(file_path)

    # Curatare nume fisier si reconstruire cale
    safe_name = sanitize_filename(target.name)
    path = target.parent / safe_name

    # Creeare directorul parinte daca nu exista
    path.parent.mkdir(parents=True, exist_ok=True)

    # Deschidem fisierul specificand flag-urile POSIX pentru creare/scriere
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    # Modul 0o600 asigura permisiunile rw------- inca de la creare
    mode = 0o600

    fd = os.open(path, flags, mode)
    mode_str = "wb" if isinstance(content, bytes) else "w"
    encoding = None if isinstance(content, bytes) else "utf-8"

    with os.fdopen(fd, mode_str, encoding=encoding) as f:
        f.write(content)

    # Asigurare suplimentara prin chmod (pentru cazurile in care fisierul exista deja)
    path.chmod(0o600)
