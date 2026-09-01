from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from triage.analyzer import analyze
from triage.defang import defang
from triage.drafter import build_draft
from triage.fetcher import fetch_from_corpus
from triage.parser import parse_report

BASE_DIR = Path(__file__).parent
PROJECT_ROOT = BASE_DIR.parents[2]
CORPUS_DIR = PROJECT_ROOT / "corpus" / "eml"

app = FastAPI(title="Phishing triage", docs_url=None, redoc_url=None)

(BASE_DIR / "static").mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def load_real_reports() -> list[dict[str, Any]]:
    """Încarcă și procesează automat toate e-mailurile din corpus/eml."""
    if not CORPUS_DIR.exists():
        return []

    eml_files = fetch_from_corpus(CORPUS_DIR)
    reports: list[dict[str, Any]] = []

    for idx, eml_path in enumerate(eml_files, start=1):
        try:
            raw_bytes = eml_path.read_bytes()
            parsed_mail = parse_report(raw_bytes)
            analysis_result = analyze(parsed_mail)
            defanged_urls = [defang(url) for url in parsed_mail.urls]

            reporter_name = parsed_mail.from_address.split("<")[0].strip() or "Coleg"
            draft_text = build_draft(analysis=analysis_result, reporter_name=reporter_name)
            evidence_list = [str(ev) for ev in analysis_result.evidence]

            verdict_val = (
                analysis_result.verdict.value
                if hasattr(analysis_result.verdict, "value")
                else str(analysis_result.verdict)
            )

            reports.append({
                "id": str(idx),
                "file_name": eml_path.name,
                "subject": parsed_mail.subject or "(Fără subiect)",
                "from_address": parsed_mail.from_address or "Necunoscut",
                "reporter": parsed_mail.from_address or "Necunoscut",
                "received_at": "N/A",
                "status": "NEW",
                "verdict": verdict_val,
                "confidence": analysis_result.confidence,
                "evidence": evidence_list,
                "defanged_urls": defanged_urls,
                "draft": draft_text,
            })
        except Exception:
            continue

    return reports

@app.get("/", response_class=HTMLResponse)
async def queue(request: Request) -> HTMLResponse:
    reports = load_real_reports()
    return templates.TemplateResponse(
        request,
        "queue.html",
        {"reports": reports},
    )


@app.get("/report/{report_id}", response_class=HTMLResponse)
async def report_detail(request: Request, report_id: str) -> HTMLResponse:
    reports = load_real_reports()
    report = next((r for r in reports if str(r.get("id")) == str(report_id)), None)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return templates.TemplateResponse(
        request,
        "detail.html",
        {"report": report},
    )

@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}