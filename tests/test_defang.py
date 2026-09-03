from __future__ import annotations

from triage.defang import defang
from triage.defang import refang
from triage.defang import strip_url_tokens

def test_defang_url() -> None:
    assert defang("https://link-rau.com/login") == "hxxps[://]link-rau[.]com/login"


def test_defang_ip() -> None:
    assert defang("192.168.1.1") == "192[.]168[.]1[.]1"


def test_defang_is_idempotent_enough() -> None:
    once = defang("http://a.b.example.ro")
    assert "[.]" in once
    assert "http://" not in once


def test_refang() -> None:
    assert refang("hxxps[://]example[.]com") == "https://example.com"

def test_strip_url_tokens_removes_sensitive_params() -> None:
    raw_url = "https://phishing.test/reset?token=abc123secret&user=ion"
    cleaned = strip_url_tokens(raw_url)

    assert "abc123secret" not in cleaned
    assert "token=[STRIPPED]" in cleaned
    assert "user=ion" in cleaned


def test_strip_url_tokens_multiple_sensitive_keys() -> None:
    raw_url = "https://login.test/auth?access_token=xyz&api_key=999&redirect=home"
    cleaned = strip_url_tokens(raw_url)

    assert "access_token=[STRIPPED]" in cleaned
    assert "api_key=[STRIPPED]" in cleaned
    assert "redirect=home" in cleaned

def test_defang_nu_stalceste_text_care_nu_e_url() -> None:
    """defang() primeste subiecte, corpuri si headere, nu doar URL-uri.
    Un subiect stricat de forma =?utf-8?B?...?= are un "?" in el, deci trecea
    prin urlencode si iesea percent-codat pe ecran."""
    subiect = "=?utf-8?B?acesta-nu-este-base64-valid!!?="
    assert defang(subiect) == subiect


def test_defang_curata_token_ul_dintr_un_url_aflat_in_text() -> None:
    text = "Confirmati aici: https://rau.example/reset?token=secret123&user=ion"
    out = defang(text)

    assert "secret123" not in out
    assert "token=[STRIPPED]" in out
    assert out.startswith("Confirmati aici: hxxps[://]")


def test_defang_pastreaza_textul_din_jurul_url_ului() -> None:
    out = defang("Va rugam accesati http://rau.example/a si confirmati.")
    assert out.startswith("Va rugam accesati ")
    assert out.endswith(" si confirmati.")


def test_strip_url_tokens_ignora_ce_nu_e_url() -> None:
    assert strip_url_tokens("doar text? cu semn de intrebare") == "doar text? cu semn de intrebare"
