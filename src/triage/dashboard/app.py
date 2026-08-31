"""FastAPI + Jinja2 + HTMX. Asculta DOAR pe 127.0.0.1."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).parent
app = FastAPI(title="Phishing triage", docs_url=None, redoc_url=None)

# Creăm directorul static dacă nu există pentru a preveni erorile de montare
(BASE_DIR / "static").mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# autoescape implicit activ. NU folosi |safe pe continut venit din mail.
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

def get_mock_reports() -> list[dict[str, Any]]:
    """Returnează lista de rapoarte din coadă."""
    # În producție/integrat, se conectează la stocarea de analize/rapoarte
    return []

@app.get("/", response_class=HTMLResponse)
async def queue(request: Request) -> HTMLResponse:
    reports = get_mock_reports()
    return templates.TemplateResponse(
        request, "queue.html", {"reports": reports}
    )

@app.get("/report/{report_id}", response_class=HTMLResponse)
async def report_detail(request: Request, report_id: str) -> HTMLResponse:
    reports = get_mock_reports()
    report = next((r for r in reports if r.get("id") == report_id), None)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return templates.TemplateResponse(
        request, "detail.html", {"report": report}
    )

@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
