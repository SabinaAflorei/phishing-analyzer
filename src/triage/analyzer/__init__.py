"""Verdictul e determinist. Fara AI aici. Fiecare semnal produce o dovada."""

from __future__ import annotations

from triage.verdicts import Analysis


def analyze(parsed: object) -> Analysis:
    """Ordinea semnalelor:
    1. fingerprint CyberReady  -> SIMULATION
    2. autentificare (SPF/DKIM/DMARC), spoofing de domeniu intern
    3. domenii lookalike (Levenshtein, homoglife, punycode/IDN), TLD-uri de risc
    4. atasamente (doar metadate)
    5. semnale de continut (pondere mica, doar coroborante)
    LEGITIMATE doar cu incredere mare; la orice indoiala -> NEEDS_REVIEW.
    """
    raise NotImplementedError
