# scripts/generate_demo_corpus.py
"""Genereaza emailuri .eml complet fictive pentru demo/screenshot-uri.
Nicio adresa, domeniu sau nume real - toate datele sunt inventate."""
from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "corpus" / "demo"


def _write_eml(filename: str, msg: EmailMessage) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
    path.write_bytes(bytes(msg))
    print(f"scris: {path}")


def make_malicious_credential_phish() -> None:
    msg = EmailMessage()
    msg["Subject"] = "Parola dumneavoastra expira azi - reautentificare necesara"
    msg["From"] = '"Serviciul IT - Exemplu Corp" <suport@exemplu-corp-it.ro>'
    msg["Reply-To"] = "raspuns@alt-domeniu-fals.com"
    msg["Authentication-Results"] = (
        "mx.exemplu.ro; spf=fail (sender IP is 198.51.100.20); "
        "dkim=fail; dmarc=fail action=quarantine"
    )
    msg.set_content(
        "Buna ziua,\n\n"
        "Parola contului dumneavoastra expira astazi. Accesati link-ul de mai jos "
        "pentru reautentificare imediata:\n\n"
        "https://portal-reset-exemplu.ru/login?token=abc123\n\n"
        "Echipa IT"
    )
    _write_eml("demo_malicious_credential_phish.eml", msg)


def make_spam_marketing() -> None:
    msg = EmailMessage()
    msg["Subject"] = "Oferta speciala - conferinta gratuita saptamana viitoare"
    msg["From"] = '"Evenimente Demo SRL" <marketing@evenimente-demo.ro>'
    msg["Authentication-Results"] = "mx.exemplu.ro; spf=pass; dkim=pass; dmarc=pass"
    msg.set_content(
        "Buna ziua,\n\n"
        "Va invitam la conferinta noastra gratuita despre tehnologie. "
        "Inregistrati-va aici: https://evenimente-demo.ro/inregistrare\n\n"
        "Pentru dezabonare, raspundeti cu STOP.\n\n"
        "Echipa Evenimente Demo"
    )
    _write_eml("demo_spam_marketing.eml", msg)


def make_legitimate_newsletter() -> None:
    msg = EmailMessage()
    msg["Subject"] = "Newsletter lunar - noutati din domeniu"
    msg["From"] = '"Partener Demo SA" <newsletter@partener-demo.ro>'
    msg["Authentication-Results"] = "mx.exemplu.ro; spf=pass; dkim=pass; dmarc=pass"
    msg.set_content(
        "Buna ziua,\n\n"
        "Va trimitem newsletter-ul lunar cu noutati din domeniu. "
        "Sper sa va fie util.\n\n"
        "Pentru dezabonare: https://partener-demo.ro/dezabonare\n\n"
        "Echipa Partener Demo"
    )
    _write_eml("demo_legitimate_newsletter.eml", msg)


def make_needs_review_screenshot() -> None:
    msg = EmailMessage()
    msg["Subject"] = "Am primit un mesaj ciudat"
    msg["From"] = '"Coleg Exemplu" <coleg@exemplu-corp.ro>'
    msg.add_attachment(
        b"[continut binar fictiv, simuland o captura de ecran]",
        maintype="image",
        subtype="png",
        filename="captura_suspecta.png",
    )
    _write_eml("demo_needs_review_screenshot.eml", msg)


def make_simulation_training() -> None:
    msg = EmailMessage()
    msg["Subject"] = "Scanare de securitate finalizata #DEMO001"
    msg["From"] = '"Notificari Sistem" <notify@platforma-simulare-demo.online>'
    msg["Message-ID"] = "<demo123@mta1.platforma-simulare-demosmtp.com>"
    msg["Authentication-Results"] = "mx.exemplu.ro; spf=pass; dkim=pass; dmarc=pass"
    msg.set_content(
        "Acesta este un mesaj generat automat.\n\n"
        "Referinta: DEMO001"
    )
    _write_eml("demo_simulation.eml", msg)


if __name__ == "__main__":
    make_malicious_credential_phish()
    make_spam_marketing()
    make_legitimate_newsletter()
    make_needs_review_screenshot()
    make_simulation_training()
    print(f"\nGata. Fisiere in {OUTPUT_DIR}")