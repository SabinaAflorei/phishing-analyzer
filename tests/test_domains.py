"""Impartirea hostname-urilor merge cu socket-urile blocate.

Testul principal e implicit: conftest blocheaza reteaua, deci daca tldextract
ar incerca sa descarce lista de sufixe, testele astea ar pica.
"""

from __future__ import annotations

import pytest

from triage.domains import is_subdomain_of, registered_domain, split_host


def test_split_host() -> None:
    assert split_host("mta1.cybereadysmtp.com") == ("mta1", "cybereadysmtp", "com")


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("trck.cybeready.net", "cybeready.net"),
        ("distributie-energle.ro", "distributie-energle.ro"),
        ("vps-217.reset-portal-energie.ru", "reset-portal-energie.ru"),
        ("a.b.co.uk", "b.co.uk"),
        ("srv01.intern.exemplu.ro", "exemplu.ro"),
    ],
)
def test_registered_domain(host: str, expected: str) -> None:
    assert registered_domain(host) == expected


def test_registered_domain_fara_sufix_public() -> None:
    assert registered_domain("192.168.1.1") == ""
    assert registered_domain("localhost") == ""


def test_is_subdomain_of_potriveste_etichete_nu_sufixe_de_text() -> None:
    assert is_subdomain_of("cybereadysmtp.com", "cybereadysmtp.com")
    assert is_subdomain_of("mta1.cybereadysmtp.com", "cybereadysmtp.com")
    # Capcana: endswith ar da True aici, si ar produce un fals pozitiv de
    # simulare pe un domeniu controlat de atacator.
    assert not is_subdomain_of("notcybereadysmtp.com", "cybereadysmtp.com")
    assert not is_subdomain_of("cybereadysmtp.com.evil.ru", "cybereadysmtp.com")
