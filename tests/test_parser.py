import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

# Modifică importul către fișierul unde se află parse_report
from triage.parser import parse_report 

# Schimbă cale_catre_un_mail.eml cu un fișier real din folderul tău de e-mailuri/teste
eml_path = Path("./corpus/eml/09_malformed_encoding.eml") 

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