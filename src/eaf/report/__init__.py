"""Report writers."""
from __future__ import annotations

import json
from pathlib import Path

from eaf.report.html_report import render_html


def write_reports(report: dict, out_dir: Path, formats: list[str], basename: str = "eaf-report") -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = {}
    if "json" in formats:
        target = out_dir / f"{basename}.json"
        target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written["json"] = target
    if "html" in formats:
        target = out_dir / f"{basename}.html"
        target.write_text(render_html(report), encoding="utf-8")
        written["html"] = target
    return written
