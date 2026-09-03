"""Baza de date. Singurul loc prin care componentele comunica intre ele.

Arhitectura din sectiunea 3 cere ca fetcher, parser, analyzer si drafter sa fie
independente: "daca Ollama e picat, verdictele se produc oricum; daca dashboard
e oprit, ingestia continua; un bug in drafter nu pierde niciodata un mail".
Asta functioneaza doar daca fiecare pas isi scrie rezultatul undeva, in loc sa
il paseze direct urmatorului. Aici e acel undeva.

Idempotenta sta pe `eml_sha256`, hash-ul fisierului brut. O repornire, un
re-poll IMAP sau un corpus recitit nu produc duplicate si nu reproceseaza nimic
(criteriul 8.3).

SQLite prin SQLAlchemy, pentru ca sunt deja in requirements. Alembic se adauga
la PRIMA schimbare de schema, nu inainte de ea.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, DateTime, Engine, Float, String, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from triage.settings import get_settings

STATUSES = ("NEW", "IN_PROGRESS", "SENT", "ESCALATED")


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Report(Base):
    """O raportare, cu tot ce s-a aflat despre ea.

    Toate campurile de text care provin din mail sunt DEFANGED inainte de a
    ajunge aici. Criteriul 8.2 cere zero URL-uri clicabile in baza de date sau
    in output, iar baza de date e locul cel mai usor de uitat.
    """

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Idempotenta. Hash-ul fisierului brut e cheia; Message-ID e a doua sansa,
    # pentru cazul in care acelasi mesaj vine cu headere de traseu diferite.
    eml_sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    message_id: Mapped[str] = mapped_column(String(512), default="", index=True)

    source: Mapped[str] = mapped_column(String(32), default="corpus")
    source_ref: Mapped[str] = mapped_column(String(512), default="")
    raw_eml_path: Mapped[str] = mapped_column(String(512), default="")

    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    reporter: Mapped[str] = mapped_column(String(512), default="")
    subject: Mapped[str] = mapped_column(String(998), default="")
    from_address: Mapped[str] = mapped_column(String(512), default="")
    report_kind: Mapped[str] = mapped_column(String(32), default="UNKNOWN")

    verdict: Mapped[str] = mapped_column(String(32), default="NEEDS_REVIEW", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list)

    headers: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    defanged_urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    attachments: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    body_text: Mapped[str] = mapped_column(String, default="")

    draft: Mapped[str] = mapped_column(String, default="")
    draft_source: Mapped[str] = mapped_column(String(16), default="template")

    status: Mapped[str] = mapped_column(String(16), default="NEW", index=True)
    # Verdictul corectat de analist. Se tine SEPARAT de cel automat: altfel
    # pierzi exact perechea (ce a zis sistemul, ce a zis omul) care e principala
    # metrica de calitate din sectiunea 8.4.
    verdict_override: Mapped[str | None] = mapped_column(String(32), default=None)
    final_draft: Mapped[str | None] = mapped_column(String, default=None)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    @property
    def effective_verdict(self) -> str:
        return self.verdict_override or self.verdict

    @property
    def was_corrected(self) -> bool:
        return bool(self.verdict_override and self.verdict_override != self.verdict)


_session_factory: sessionmaker[Session] | None = None
_engine: Engine | None = None


def make_engine(db_path: Path | str) -> Engine:
    """Motor SQLite pe un fisier, cu permisiuni restrictive.

    Baza contine mail-uri raportate: nume de colegi, adrese si continut. Intra
    sub aceleasi reguli ca .eml-urile brute (sectiunea 4.5), deci 0700 pe
    director si 0600 pe fisier.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)  # noqa: PTH101 - avem deja Path, chmod e explicit

    engine = create_engine(f"sqlite:///{path}", future=True)
    Base.metadata.create_all(engine)

    if path.exists():
        path.chmod(0o600)
    return engine


def use_database(db_path: Path | str) -> None:
    """Leaga procesul de o baza de date. Testele o cheama cu tmp_path."""
    global _session_factory, _engine
    _engine = make_engine(db_path)
    _session_factory = sessionmaker(bind=_engine, expire_on_commit=False)


@contextmanager
def session() -> Iterator[Session]:
    """O sesiune, cu commit la iesire si rollback la exceptie."""
    if _session_factory is None:
        use_database(get_settings().paths.db_path)
    assert _session_factory is not None
    with _session_factory() as s:
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise


# ---------------------------------------------------------------------------
# Operatii
# ---------------------------------------------------------------------------


def already_ingested(s: Session, eml_sha256: str, message_id: str = "") -> bool:
    """Idempotenta la repornire si la re-poll (criteriile 8.3 si I9)."""
    if s.scalar(select(Report.id).where(Report.eml_sha256 == eml_sha256)):
        return True
    return bool(
        message_id and s.scalar(select(Report.id).where(Report.message_id == message_id))
    )


def save_report(s: Session, **fields: Any) -> Report | None:
    """Insereaza un raport nou. Intoarce None daca exista deja."""
    sha = str(fields["eml_sha256"])
    if already_ingested(s, sha, str(fields.get("message_id", ""))):
        return None
    report = Report(**fields)
    s.add(report)
    s.flush()
    return report


def list_reports(
    s: Session, *, status: str | None = None, verdict: str | None = None
) -> list[Report]:
    query = select(Report).order_by(Report.ingested_at.desc(), Report.id.desc())
    if status:
        query = query.where(Report.status == status)
    if verdict:
        query = query.where(
            func.coalesce(Report.verdict_override, Report.verdict) == verdict
        )
    return list(s.scalars(query))


def get_report(s: Session, report_id: int) -> Report | None:
    return s.get(Report, report_id)


def set_status(s: Session, report_id: int, status: str) -> bool:
    if status not in STATUSES:
        raise ValueError(f"Status necunoscut: {status!r}. Permise: {', '.join(STATUSES)}")
    report = s.get(Report, report_id)
    if report is None:
        return False
    report.status = status
    return True


def set_verdict_override(s: Session, report_id: int, verdict: str) -> bool:
    report = s.get(Report, report_id)
    if report is None:
        return False
    report.verdict_override = verdict
    return True


def save_final_draft(s: Session, report_id: int, final_draft: str) -> bool:
    report = s.get(Report, report_id)
    if report is None:
        return False
    report.final_draft = final_draft
    return True


def quality_stats(s: Session) -> dict[str, Any]:
    """Metricile din 8.4, calculate din baza de date, nu dintr-un fisier lateral.

    Rata de acceptare a draft-urilor, distributia de verdicte si matricea de
    corectii: care verdict e cel mai des corectat, si in ce e schimbat. Ultima e
    informatia care iti spune unde sa te uiti.
    """
    reports = list(s.scalars(select(Report)))
    with_draft = [r for r in reports if r.final_draft is not None]
    unchanged = sum(1 for r in with_draft if r.final_draft == r.draft)
    corrected = [r for r in reports if r.was_corrected]

    distribution: dict[str, int] = {}
    for report in reports:
        distribution[report.effective_verdict] = distribution.get(report.effective_verdict, 0) + 1

    matrix: dict[str, dict[str, int]] = {}
    for report in corrected:
        target = str(report.verdict_override)
        matrix.setdefault(report.verdict, {})
        matrix[report.verdict][target] = matrix[report.verdict].get(target, 0) + 1

    by_status: dict[str, int] = {st: 0 for st in STATUSES}
    for report in reports:
        by_status[report.status] = by_status.get(report.status, 0) + 1

    return {
        "total_reports": len(reports),
        "total_drafts_sent": len(with_draft),
        "unchanged_drafts": unchanged,
        "acceptance_rate": round(unchanged / len(with_draft) * 100, 1) if with_draft else 100.0,
        "overrides_count": len(corrected),
        "correction_rate": round(len(corrected) / len(reports) * 100, 1) if reports else 0.0,
        "verdict_distribution": dict(sorted(distribution.items(), key=lambda kv: -kv[1])),
        "correction_matrix": matrix,
        "by_status": by_status,
    }


def to_dict(report: Report) -> dict[str, Any]:
    """Reprezentarea folosita de dashboard si de CLI-ul cu --json."""
    return {
        "id": report.id,
        "eml_sha256": report.eml_sha256,
        "source": report.source,
        "source_ref": report.source_ref,
        "received_at": report.received_at.isoformat(),
        "reporter": report.reporter,
        "subject": report.subject,
        "from_address": report.from_address,
        "report_kind": report.report_kind,
        "verdict": report.effective_verdict,
        "auto_verdict": report.verdict,
        "verdict_override": report.verdict_override,
        "was_corrected": report.was_corrected,
        "confidence": report.confidence,
        "score": report.score,
        "evidence": report.evidence,
        "headers": report.headers,
        "defanged_urls": report.defanged_urls,
        "attachments": report.attachments,
        "body_text": report.body_text,
        "draft": report.final_draft if report.final_draft is not None else report.draft,
        "draft_source": report.draft_source,
        "status": report.status,
    }


def dump_json(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False)
