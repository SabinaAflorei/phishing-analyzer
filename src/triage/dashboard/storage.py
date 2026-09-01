from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DATA_DIR = Path("data")
FEEDBACK_FILE = DATA_DIR / "feedback.json"


def _ensure_storage() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not FEEDBACK_FILE.exists():
        FEEDBACK_FILE.write_text(json.dumps({"reports_override": {}, "draft_edits": []}))


def save_verdict_override(report_id: str, new_verdict: str) -> None:
    _ensure_storage()
    data = json.loads(FEEDBACK_FILE.read_text())
    data["reports_override"][report_id] = new_verdict
    FEEDBACK_FILE.write_text(json.dumps(data, indent=2))


def save_draft_edit(report_id: str, original_draft: str, final_draft: str) -> None:
    _ensure_storage()
    data = json.loads(FEEDBACK_FILE.read_text())
    data["draft_edits"].append({
        "report_id": report_id,
        "original": original_draft,
        "final": final_draft,
        "is_modified": original_draft.strip() != final_draft.strip(),
    })
    FEEDBACK_FILE.write_text(json.dumps(data, indent=2))


def get_feedback_stats() -> dict[str, Any]:
    _ensure_storage()
    data = json.loads(FEEDBACK_FILE.read_text())
    edits = data.get("draft_edits", [])
    total_edits = len(edits)
    unchanged = sum(1 for e in edits if not e["is_modified"])
    
    rate = (unchanged / total_edits * 100) if total_edits > 0 else 100.0
    return {
        "total_processed": total_edits,
        "unchanged_drafts": unchanged,
        "acceptance_rate": round(rate, 1),
        "overrides_count": len(data.get("reports_override", {})),
    }