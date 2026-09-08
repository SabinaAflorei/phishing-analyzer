import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

# Modifică importul către fișierul unde se află parse_report
from triage.parser import parse_report 
from triage.parser import extract_forwarded_headers
import struct

# Schimbă cale_catre_un_mail.eml cu un fișier real din folderul tău de e-mailuri/teste
eml_path = Path("./corpus/eml/09_malformed_encoding.eml") 

def test_extract_forwarded_headers_ro():
    body = (
        "Buna ziua,\n\nVa rog verificati acest mesaj.\n\n"
        "---------- Mesaj redirecționat ----------\n"
        "De la: Atacator <fake@rau.com>\n"
        "Trimis: luni, 1 ianuarie 2026\n"
        "Către: coleg@exemplu.ro\n"
        "Subiect: Factura restanta\n\n"
        "Corp original aici."
    )
    result = extract_forwarded_headers(body)
    assert result["from"] == "Atacator <fake@rau.com>"
    assert result["subject"] == "Factura restanta"


def test_extract_forwarded_headers_en():
    body = (
        "-------- Forwarded message --------\n"
        "From: attacker@evil.com\n"
        "Sent: Monday, January 1, 2026\n"
        "To: colleague@example.com\n"
        "Subject: Invoice overdue\n\n"
        "body"
    )
    result = extract_forwarded_headers(body)
    assert result["from"] == "attacker@evil.com"
    assert result["subject"] == "Invoice overdue"


def test_extract_forwarded_headers_no_match_returns_empty():
    assert extract_forwarded_headers("Just a normal reply, no forward block.") == {}


# TODO(curatenie): cele trei teste de mai sus sunt bune, dar blocul de mai jos nu
# e un test - e cod la nivel de modul care ruleaza la COLECTARE, printeaza si nu
# verifica nimic. Pytest il "trece" mereu, deci umfla acoperirea fara sa dea niciun
# semnal. In plus depinde de corpus/eml/, care e in .gitignore, deci pe orice alta
# masina doar printeaza "nu a fost gasit".
# Cum rezolvi: sterge blocul, sau transforma-l intr-un test adevarat, cu un .eml
# mic construit inline in test (bytes literali), ca sa ruleze si fara corpus.
# Sterge si sys.path.insert de la inceputul fisierului - pachetul se instaleaza cu
# "pip install -e .", nu are nevoie de carje.
if eml_path.exists():
    raw_data = eml_path.read_bytes()
    parsed = parse_report(raw_data)
    
    print("\n--- TEST PARSER EMAIL ---")
    print("SUBIECT:", parsed.subject)
    print("BODY TEXT (primele 200 caractere):")
    print(repr(parsed.body_text[:200]))
    print("LUNGIME BODY:", len(parsed.body_text))
else:
    print(f"Fișierul {eml_path} nu a fost găsit pentru testare!")

def _fake_zip_bytes(encrypted: bool) -> bytes:
    flags = 0x0001 if encrypted else 0x0000
    header = b"PK\x03\x04" + b"\x14\x00" + struct.pack("<H", flags) + b"\x00" * 22
    return header


def test_zip_is_encrypted_detects_flag():
    from triage.parser import _zip_is_encrypted
    assert _zip_is_encrypted(_fake_zip_bytes(encrypted=True)) is True
    assert _zip_is_encrypted(_fake_zip_bytes(encrypted=False)) is False


def test_zip_is_encrypted_non_zip_returns_false():
    from triage.parser import _zip_is_encrypted
    assert _zip_is_encrypted(b"not a zip file") is False    