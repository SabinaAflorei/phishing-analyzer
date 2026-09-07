from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from triage.db import get_report, get_session, init_db, list_reports
from triage.dashboard.feedback_store import get_feedback_stats, save_draft_edit, save_verdict_override
from triage.parser import decode_mime_header

from triage.db import ReportRow

logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).parent

VALID_STATUSES = {"NEW", "SENT", "ESCALATED"}
VALID_VERDICTS = {"SIMULATION", "MALICIOUS", "SPAM", "LEGITIMATE", "NEEDS_REVIEW"}

app = FastAPI(title="Phishing triage", docs_url=None, redoc_url=None)

(BASE_DIR / "static").mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.filters["decode_mime"] = decode_mime_header


@app.on_event("startup")
def _startup() -> None:
    init_db()


def _row_to_dict(row: ReportRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "file_name": row.file_name,
        "subject": row.subject,
        "from_address": row.from_address,
        "reporter": row.reporter,
        "headers": json.loads(row.headers_json or "{}"),
        "status": row.status,
        "verdict": row.verdict_override or row.verdict,
        "verdict_original": row.verdict,
        "confidence": row.confidence,
        "evidence": json.loads(row.evidence_json or "[]"),
        "defanged_urls": json.loads(row.defanged_urls_json or "[]"),
        "body_text": row.body_text,
        "draft": row.draft_final or row.draft,
        "attachments": json.loads(row.attachments_json or "[]"),
    }


@app.get("/", response_class=HTMLResponse)
async def queue(request: Request) -> HTMLResponse:
    session = get_session()
    reports = [_row_to_dict(r) for r in list_reports(session)]
    session.close()
    return templates.TemplateResponse(request, "queue.html", {"reports": reports})


@app.get("/report/{report_id}", response_class=HTMLResponse)
async def report_detail(request: Request, report_id: str) -> HTMLResponse:
    session = get_session()
    row = get_report(session, report_id)
    session.close()
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    return templates.TemplateResponse(request, "detail.html", {"report": _row_to_dict(row)})


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/stats", response_class=HTMLResponse)
async def stats_page(request: Request) -> HTMLResponse:
    stats = get_feedback_stats()
    return templates.TemplateResponse(request, "stats.html", {"stats": stats})


@app.post("/report/{report_id}/action")
async def handle_report_action(
    request: Request,
    report_id: str,
    action: str = Form(...),
    final_draft: str = Form(None),
    corrected_verdict: str = Form(None),
) -> HTMLResponse:
    session = get_session()
    row = get_report(session, report_id)
    if not row:
        session.close()
        raise HTTPException(status_code=404, detail="Report not found")

    message = f"Acțiune '{action}' înregistrată cu succes."

    if action == "save_draft" and final_draft:
        save_draft_edit(report_id, row.draft, final_draft)
        row.draft_final = final_draft
        session.commit()

    elif action == "override_verdict" and corrected_verdict:
        if corrected_verdict not in VALID_VERDICTS:
            session.close()
            raise HTTPException(status_code=400, detail="Verdict invalid")
        save_verdict_override(report_id, corrected_verdict)
        row.verdict_override = corrected_verdict
        session.commit()

    elif action == "mark_sent":
        row.status = "SENT"
        session.commit()

    elif action == "escalate":
        row.status = "ESCALATED"
        session.commit()

    else:
        message = f"Acțiune necunoscută: '{action}'."

    report_dict = _row_to_dict(row)
    session.close()

    return templates.TemplateResponse(
        request, "detail.html", {"report": report_dict, "message": message}
    )


@app.post("/bulk-action")
async def handle_bulk_action(
    request: Request,
    selected_ids: Annotated[list[str], Form(default_factory=list)],
    bulk_status: Annotated[str, Form(...)],
) -> HTMLResponse:
    if bulk_status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail="Status invalid")

    session = get_session()
    updated = 0
    for report_id in selected_ids:
        row = get_report(session, report_id)
        if row:
            row.status = bulk_status
            updated += 1
    session.commit()

    reports = [_row_to_dict(r) for r in list_reports(session)]
    session.close()

    return templates.TemplateResponse(
        request,
        "queue.html",
        {"reports": reports, "message": f"Statusul a fost actualizat pentru {updated} rapoarte."},
    )