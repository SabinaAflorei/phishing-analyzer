import stat
import sys
from pathlib import Path

import pytest

from triage.secure_files import sanitize_filename, save_secure_file


def test_sanitize_filename_prevents_path_traversal() -> None:
    assert sanitize_filename("../../etc/passwd") == "passwd"


def test_sanitize_filename_removes_special_chars() -> None:
    assert sanitize_filename("file;<script>.exe") == "file__script_.exe"


# Pe Windows testul asta ar pica cu "438 != 384" (0o666 in loc de 0o600): acolo
# nu exista permisiuni POSIX, iar chmod doar comuta read-only. Nu e nimic de
# reparat in cod - dar o suita in care "unul pica mereu" te obisnuieste sa
# ignori esecurile, si atunci ratezi si pe cel care conteaza.
@pytest.mark.skipif(sys.platform == "win32", reason="permisiuni POSIX")
def test_save_secure_file_permissions(tmp_path: Path) -> None:
    test_file = tmp_path / "test_email.eml"
    save_secure_file(test_file, "From: test@example.com\nSubject: Test")

    assert test_file.exists()

    # Extrage permisiunile fisierului
    file_stat = test_file.stat()
    file_mode = stat.S_IMODE(file_stat.st_mode)

    # Verifica daca permisiunile sunt exact 0o600 (rw-------)
    assert file_mode == 0o600


def test_directorul_cu_date_e_exclus_din_backup(tmp_path: Path) -> None:
    """Sectiunea 4.5. CACHEDIR.TAG e respectat de borg, restic si
    `tar --exclude-caches`, deci protectia functioneaza fara ca cineva sa isi
    aduca aminte sa configureze o excludere."""
    from triage.db import use_database

    use_database(tmp_path / "data" / "db" / "triage.sqlite3")
    tag = tmp_path / "data" / "CACHEDIR.TAG"

    assert tag.is_file()
    assert tag.read_text(encoding="utf-8").startswith("Signature: 8a477f597d28d172789f06886806bc55")


@pytest.mark.skipif(sys.platform == "win32", reason="permisiuni POSIX")
def test_permisiuni_restrictive_pe_baza_de_date(tmp_path: Path) -> None:
    from triage.db import use_database

    db_path = tmp_path / "data" / "db" / "triage.sqlite3"
    use_database(db_path)

    assert db_path.stat().st_mode & 0o777 == 0o600
    assert db_path.parent.stat().st_mode & 0o777 == 0o700
