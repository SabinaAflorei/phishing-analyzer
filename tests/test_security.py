import os
import stat
from pathlib import Path
from triage.storage import save_secure_file 

def test_save_secure_file_permissions(tmp_path: Path) -> None:
    test_file = tmp_path / "test_email.eml"
    save_secure_file(test_file, "From: test@example.com\nSubject: Test")
    
    assert test_file.exists()
    
    # Extrage permisiunile fisierului
    file_stat = test_file.stat()
    file_mode = stat.S_IMODE(file_stat.st_mode)
    
    # Verifica daca permisiunile sunt exact 0o600 (rw-------)
    assert file_mode == 0o600