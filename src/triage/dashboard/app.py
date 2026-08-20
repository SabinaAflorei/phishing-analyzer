"""FastAPI + Jinja2 + HTMX. Asculta DOAR pe 127.0.0.1."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).parent
app = FastAPI(title="Phishing triage", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# autoescape implicit activ. NU folosi |safe pe continut venit din mail.
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.get("/", response_class=HTMLResponse)
async def queue(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "queue.html", {"reports": []})


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
