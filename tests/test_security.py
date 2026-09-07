import stat
import sys
import pytest
from pathlib import Path
from triage.secure_files import sanitize_filename, save_secure_file 

def test_sanitize_filename_prevents_path_traversal() -> None:
    assert sanitize_filename("../../etc/passwd") == "passwd"

def test_sanitize_filename_removes_special_chars() -> None:
    assert sanitize_filename("file;<script>.exe") == "file__script_.exe"

@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows nu are permisiuni POSIX - chmod doar comuta read-only, "
           "0o600 devine 0o666. Nimic de reparat in secure_files.py, doar "
           "o limitare de mediu. Pe CI (ubuntu-24.04) testul ruleaza normal.",
)
def test_save_secure_file_permissions(tmp_path: Path) -> None:
    test_file = tmp_path / "test_email.eml"
    save_secure_file(test_file, "From: test@example.com\nSubject: Test")

    assert test_file.exists()

    # Extrage permisiunile fisierului
    file_stat = test_file.stat()
    file_mode = stat.S_IMODE(file_stat.st_mode)

    # Verifica daca permisiunile sunt exact 0o600 (rw-------)
    assert file_mode == 0o600    