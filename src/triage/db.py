"""Persistenta SQLite. Reports se scriu o singura data la ingestie
(fetcher -> parser -> analyzer -> drafter); dashboard-ul doar citeste
si actualizeaza status / verdict override / draft final."""

from __future__ import annotations

from datetime import datetime, UTC
from pathlib import Path

from sqlalchemy import DateTime, Float, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.orm import Mapped, mapped_column
from typing import Any

class Base(DeclarativeBase):
    pass


class ReportRow(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    file_name: Mapped[str] = mapped_column(String, nullable=False)
    subject: Mapped[str] = mapped_column(Text, default="")
    from_address: Mapped[str] = mapped_column(Text, default="")
    reporter: Mapped[str] = mapped_column(Text, default="")
    verdict: Mapped[str] = mapped_column(String, nullable=False)
    verdict_override: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")
    defanged_urls_json: Mapped[str] = mapped_column(Text, default="[]")
    body_text: Mapped[str] = mapped_column(Text, default="")
    draft: Mapped[str] = mapped_column(Text, default="")
    draft_final: Mapped[str | None] = mapped_column(Text, nullable=True)
    attachments_json: Mapped[str] = mapped_column(Text, default="[]")
    headers_json: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String, default="NEW")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )


DEFAULT_DB_PATH = Path("data") / "db" / "triage.sqlite3"

_engine = None
_SessionLocal: sessionmaker[Session] | None = None


def init_db(db_path: Path | None = None) -> None:
    global _engine, _SessionLocal
    if db_path is None:
        from triage.settings import get_db_path
        db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _engine = create_engine(f"sqlite:///{db_path}", future=True)
    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine, future=True)


def get_session() -> Session:
    global _SessionLocal
    if _SessionLocal is None:
        init_db()
    assert _SessionLocal is not None
    return _SessionLocal()


def report_id_for(raw_bytes: bytes) -> str:
    """Hash stabil al continutului brut - PK idempotent: acelasi fisier
    la repornire produce acelasi id, deci UPSERT, niciodata duplicare."""
    import hashlib
    return hashlib.sha256(raw_bytes).hexdigest()[:16]


def upsert_report(session: Session, data: dict[str, Any]) -> None:
    existing = session.get(ReportRow, data["id"])
    if existing:
        # NU suprascriem status / verdict_override / draft_final -
        # alea sunt decizii de analist, nu rezultate ale pipeline-ului
        for field in (
            "subject", "verdict", "confidence", "evidence_json",
            "defanged_urls_json", "body_text", "draft",
            "attachments_json", "headers_json",
        ):
            setattr(existing, field, data[field])
        existing.updated_at = datetime.now(UTC)
    else:
        session.add(ReportRow(**data))
    session.commit()


def list_reports(session: Session) -> list[ReportRow]:
    return list(session.scalars(select(ReportRow).order_by(ReportRow.created_at.desc())))


def get_report(session: Session, report_id: str) -> ReportRow | None:
    return session.get(ReportRow, report_id)