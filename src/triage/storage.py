import os
from pathlib import Path

def save_secure_file(file_path: Path | str, content: bytes | str) -> None:
    """Salvează un fișier pe disc setând permisiunile la 0o600 (rw-------)."""
    path = Path(file_path)
    
    # Creeare directorul parinte daca nu exista
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Deschidem fisierul specificand flag-urile POSIX pentru creare/scriere
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    # Modul 0o600 asigura permisiunile rw------- inca de la creare
    mode = 0o600
    
    fd = os.open(path, flags, mode)
    with open(fd, "wb" if isinstance(content, bytes) else "w", encoding=None if isinstance(content, bytes) else "utf-8") as f:
        f.write(content)
        
    # Asigurare suplimentara prin chmod (pentru cazurile in care fisierul exista deja)
    os.chmod(path, 0o600)