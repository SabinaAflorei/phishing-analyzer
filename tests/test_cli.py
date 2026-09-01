from __future__ import annotations

from pathlib import Path

import pytest

from triage.cli import process_eml


def test_process_eml_not_found(tmp_path: Path) -> None:
    missing_file = tmp_path / "missing.eml"
    exit_code = process_eml(missing_file)
    assert exit_code == 1


def test_process_eml_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    eml_file = tmp_path / "sample.eml"
    eml_file.write_text(
        "From: test@example.com\nSubject: Test\n\nHello http://example.com",
        encoding="utf-8",
    )
    exit_code = process_eml(eml_file, output_json=True)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert '"verdict"' in captured.out