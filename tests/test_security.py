import stat
from pathlib import Path
from triage.storage import sanitize_filename, save_secure_file 

def test_sanitize_filename_prevents_path_traversal() -> None:
    assert sanitize_filename("../../etc/passwd") == "passwd"

def test_sanitize_filename_removes_special_chars() -> None:
    assert sanitize_filename("file;<script>.exe") == "file__script_.exe"

# TODO(nu e bug, e nota de mediu): testul asta pica pe Windows cu "438 != 384",
# adica 0o666 in loc de 0o600, pentru ca Windows nu are permisiuni POSIX - chmod
# doar comuta read-only. In CI, pe ubuntu-24.04, trece.
# Nu e nimic de reparat in triage/storage.py. Dar inseamna ca nu poti avea suita
# verde local pe Windows, si e usor sa te obisnuiesti cu "unul pica mereu" si sa
# ratezi altul care incepe sa pice.
# Cum rezolvi: marcheaza-l cu
#   @pytest.mark.skipif(sys.platform == "win32", reason="permisiuni POSIX")
def test_save_secure_file_permissions(tmp_path: Path) -> None:
    test_file = tmp_path / "test_email.eml"
    save_secure_file(test_file, "From: test@example.com\nSubject: Test")
    
    assert test_file.exists()
    
    # Extrage permisiunile fisierului
    file_stat = test_file.stat()
    file_mode = stat.S_IMODE(file_stat.st_mode)
    
    # Verifica daca permisiunile sunt exact 0o600 (rw-------)
    assert file_mode == 0o600