"""Extrage mesajul ORIGINAL, nu wrapper-ul colegului care a raportat."""

from __future__ import annotations

from enum import StrEnum


class ReportKind(StrEnum):
    FORWARD_INLINE = "FORWARD_INLINE"
    ATTACHED_EML = "ATTACHED_EML"
    SCREENSHOT_ONLY = "SCREENSHOT_ONLY"  # -> NEEDS_REVIEW
    UNKNOWN = "UNKNOWN"


def detect_report_kind(raw: bytes) -> ReportKind:
    raise NotImplementedError


def parse_report(raw: bytes) -> object:
    """Headere, Authentication-Results, Received chain, From/Reply-To/Return-Path,
    subiect, corp text, URL-uri (extrase si din HTML - HTML-ul NU se afiseaza),
    atasamente (nume, sha256, tip, dimensiune)."""
    raise NotImplementedError 