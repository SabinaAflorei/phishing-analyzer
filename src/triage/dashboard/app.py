"""Dashboard-ul analistului. Citeste din baza de date, nu reparseaza corpusul.

Pana acum fiecare cerere HTTP reparsa tot corpusul de la zero, iar statusul si
corectiile de verdict traiau doar cat un raspuns. Acum sunt patru rute care
citesc si scriu in `reports`, deci ce apesi ramane apasat.

Toate actiunile POST se termina cu un redirect (303). Fara el, un refresh dupa
"Marcheaza trimis" retrimite formularul.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from triage import db
from triage.db import STATUSES, quality_stats, session, to_dict
from triage.pipeline import ingest_once
from triage.verdicts import Verdict

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent

app = FastAPI(title="Triaj phishing", docs_url=None, redoc_url=None)

(BASE_DIR / "static").mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Mesajele de confirmare se trec prin URL ca ATOM, nu ca text liber: ce vine din
# query string nu ajunge niciodata in pagina.
MESSAGES = {
    "draft_saved": "Draftul a fost salvat.",
    "verdict_saved": "Verdictul corectat a fost salvat.",
    "marked_sent": "Raportul a fost marcat ca trimis.",
    "escalated": "Raportul a fost escaladat.",
    "bulk_done": "Statusul a fost actualizat pentru rapoartele selectate.",
    "ingested": "Ingestie terminată.",
    "nothing": "Nu s-a schimbat nimic.",
}

VERDICTS = [v.value for v in Verdict]

STATUS_LABELS = {
    "NEW": "Nou",
    "IN_PROGRESS": "În lucru",
    "SENT": "Trimis",
    "ESCALATED": "Escaladat",
}

VERDICT_LABELS = {
    "SIMULATION": "Simulare",
    "MALICIOUS": "Periculos",
    "SPAM": "Spam",
    "LEGITIMATE": "Legitim",
    "NEEDS_REVIEW": "De verificat",
}

templates.env.globals["STATUS_LABELS"] = STATUS_LABELS
templates.env.globals["VERDICT_LABELS"] = VERDICT_LABELS
templates.env.globals["STATUSES"] = STATUSES
templates.env.globals["VERDICTS"] = VERDICTS


def _flash(request: Request) -> str | None:
    return MESSAGES.get(request.query_params.get("msg", ""))


def _redirect(target: str, msg: str) -> RedirectResponse:
    return RedirectResponse(url=f"{target}?msg={msg}", status_code=303)


@app.get("/", response_class=HTMLResponse)
async def queue(request: Request) -> HTMLResponse:
    status = request.query_params.get("status") or None
    verdict = request.query_params.get("verdict") or None

    with session() as s:
        reports = [to_dict(r) for r in db.list_reports(s, status=status, verdict=verdict)]
        counts = quality_stats(s)

    return templates.TemplateResponse(
        request,
        "queue.html",
        {
            "reports": reports,
            "active_status": status,
            "active_verdict": verdict,
            "counts": counts,
            "active_page": "queue",
            "message": _flash(request),
        },
    )


@app.get("/report/{report_id}", response_class=HTMLResponse)
async def report_detail(request: Request, report_id: int) -> HTMLResponse:
    with session() as s:
        report = db.get_report(s, report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Raportul nu există")
        data = to_dict(report)
        data["evidence_rows"] = report.evidence
        data["auto_draft"] = report.draft

    return templates.TemplateResponse(
        request,
        "detail.html",
        {"report": data, "active_page": "queue", "message": _flash(request)},
    )


@app.post("/report/{report_id}/action")
async def handle_report_action(
    report_id: int,
    action: Annotated[str, Form()],
    final_draft: Annotated[str | None, Form()] = None,
    corrected_verdict: Annotated[str | None, Form()] = None,
) -> RedirectResponse:
    """Cele patru actiuni ale analistului.

    "Marcheaza trimis" si "Escaleaza" cadeau pana acum pe o ramura inexistenta:
    raspunsul zicea "Actiune inregistrata cu succes" si nu se salva nimic. Un
    mesaj de succes mincinos e mai rau decat o eroare, pentru ca ascunde
    problema. Acum o actiune necunoscuta spune ca nu s-a schimbat nimic.
    """
    target = f"/report/{report_id}"

    with session() as s:
        if db.get_report(s, report_id) is None:
            raise HTTPException(status_code=404, detail="Raportul nu există")

        if action == "save_draft" and final_draft is not None:
            db.save_final_draft(s, report_id, final_draft)
            return _redirect(target, "draft_saved")

        if action == "override_verdict" and corrected_verdict in VERDICTS:
            db.set_verdict_override(s, report_id, corrected_verdict)
            return _redirect(target, "verdict_saved")

        if action == "mark_sent":
            db.set_status(s, report_id, "SENT")
            return _redirect(target, "marked_sent")

        if action == "escalate":
            db.set_status(s, report_id, "ESCALATED")
            return _redirect(target, "escalated")

    logger.warning("Actiune necunoscuta pe raportul %s: %r", report_id, action)
    return _redirect(target, "nothing")


@app.post("/bulk-action")
async def handle_bulk_action(
    bulk_status: Annotated[str, Form()],
    selected_ids: Annotated[list[str], Form()] = [],  # noqa: B006 - FastAPI cere valoarea
) -> RedirectResponse:
    if bulk_status not in STATUSES:
        raise HTTPException(status_code=400, detail="Status necunoscut")

    with session() as s:
        for raw_id in selected_ids:
            if raw_id.isdigit():
                db.set_status(s, int(raw_id), bulk_status)

    return _redirect("/", "bulk_done")


@app.post("/ingest")
async def trigger_ingest() -> RedirectResponse:
    """Ruleaza un ciclu de ingestie. Idempotent, deci apasabil oricand."""
    result = ingest_once()
    logger.info("Ingestie din dashboard: %s", result)
    return _redirect("/", "ingested")


@app.get("/stats", response_class=HTMLResponse)
async def stats_page(request: Request) -> HTMLResponse:
    with session() as s:
        stats: dict[str, Any] = quality_stats(s)
    return templates.TemplateResponse(
        request, "stats.html", {"stats": stats, "active_page": "stats"}
    )


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
