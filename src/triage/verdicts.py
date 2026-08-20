"""Categoriile de verdict si structurile de dovezi."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Verdict(StrEnum):
    SIMULATION = "SIMULATION"
    MALICIOUS = "MALICIOUS"
    SPAM = "SPAM"
    LEGITIMATE = "LEGITIMATE"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class Evidence:
    """O dovada = un semnal, cu explicatie lizibila pentru analist si post-mortem."""

    code: str
    severity: Severity
    description: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Analysis:
    verdict: Verdict
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)
