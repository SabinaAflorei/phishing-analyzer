from __future__ import annotations

from triage.defang import defang


def test_defang_url() -> None:
    assert defang("https://link-rau.com/login") == "hxxps[://]link-rau[.]com/login"


def test_defang_ip() -> None:
    assert defang("192.168.1.1") == "192[.]168[.]1[.]1"


def test_defang_is_idempotent_enough() -> None:
    once = defang("http://a.b.example.ro")
    assert "[.]" in once
    assert "http://" not in once
