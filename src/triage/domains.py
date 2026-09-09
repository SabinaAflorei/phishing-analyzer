"""Impartirea unui hostname in subdomeniu / domeniu / sufix public, strict offline.

De ce exista fisierul asta in loc sa apelezi tldextract direct: tldextract, cu
setarile lui implicite, descarca lista de sufixe publice de la publicsuffix.org
la prima folosire si o tine intr-un cache legat de calea venv-ului. Adica:

- pe VM-ul tau merge, pentru ca cineva a incalzit cache-ul o data;
- in CI, pe un venv nou, face un request HTTP la pornire;
- in teste, unde socket-urile sunt blocate, pica cu o eroare care nu seamana
  deloc cu cauza reala.

Un sistem descris ca offline-first nu are voie sa iasa in retea ca sa afle ce e
un TLD. `suffix_list_urls=()` forteaza folosirea instantaneului impachetat in
pachet, deci comportamentul e identic pe orice masina si la orice moment.

Instantaneul e fix. Cand apar TLD-uri noi, se actualizeaza tldextract in
requirements.txt - deliberat, cu un PR, nu pe tacute la runtime.
"""

from __future__ import annotations

from functools import lru_cache

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)


@lru_cache(maxsize=4096)
def split_host(host: str) -> tuple[str, str, str]:
    """('mta1.cybereadysmtp.com') -> ('mta1', 'cybereadysmtp', 'com')"""
    result = _EXTRACT(host.strip().rstrip(".").lower())
    return result.subdomain, result.domain, result.suffix


def registered_domain(host: str) -> str:
    """Domeniul inregistrabil: 'mta1.cybereadysmtp.com' -> 'cybereadysmtp.com'.

    Sir gol daca hostname-ul nu are sufix public valid (IP-uri, nume interne).
    """
    _, domain, suffix = split_host(host)
    return f"{domain}.{suffix}" if domain and suffix else ""


def is_subdomain_of(host: str, parent: str) -> bool:
    """Potrivire exacta sau subdomeniu propriu-zis.

    Contine intentionat comparatia pe eticheta, nu `endswith`: altfel
    'notcybereadysmtp.com' ar trece drept subdomeniu al 'cybereadysmtp.com',
    iar un fals pozitiv pe fingerprint-ul de simulare e exact ce nu ai voie
    sa produci (sectiunea 8.1).
    """
    host = host.strip().rstrip(".").lower()
    parent = parent.strip().rstrip(".").lower()
    return host == parent or host.endswith("." + parent)
