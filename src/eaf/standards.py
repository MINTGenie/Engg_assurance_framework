"""Mapping of check results onto categories of public standards (evidence, not compliance)."""
from __future__ import annotations

import tomllib
from importlib import resources

from eaf.models import CheckResult, Status

_ORDER = [Status.FAIL, Status.WARNING, Status.NOT_EXECUTED, Status.PASS, Status.NOT_APPLICABLE]


def load_standards() -> list[dict]:
    path = resources.files("eaf") / "data" / "standards" / "coverage.toml"
    return tomllib.loads(path.read_text(encoding="utf-8")).get("standard", [])


def standards_coverage(results: list[CheckResult]) -> list[dict]:
    by_id = {r.id: r for r in results}
    out = []
    for std in load_standards():
        categories = []
        for cat in std.get("category", []):
            mapped = [by_id[c] for c in cat.get("checks", []) if c in by_id]
            executed = [r for r in mapped if r.status in (Status.PASS, Status.WARNING, Status.FAIL)]
            whole = set(cat.get("all_findings_of", []))
            # A finding belongs to the category if it is tagged with it, or comes from a check
            # that is entirely about this category (e.g. dependency audits for A06).
            hits = [(r, f) for r in results for f in r.findings if not f.suppressed
                    and (cat["id"] in f.standards or r.id in whole)]
            tagged = len(hits)
            if not cat.get("checks"):
                coverage, status = "none", Status.NOT_EXECUTED
            elif not executed:
                coverage = "none"
                status = min((r.status for r in mapped), key=_ORDER.index) if mapped else Status.NOT_EXECUTED
            else:
                coverage = "partial"
                with_hits = {r.id: r.status for r, _ in hits if r.status in (Status.FAIL, Status.WARNING)}
                if with_hits:
                    status = min(with_hits.values(), key=_ORDER.index)
                elif any(r.status is Status.NOT_EXECUTED for r in mapped):
                    status = Status.NOT_EXECUTED   # part of the evidence is missing
                else:
                    status = Status.PASS
            categories.append({
                "id": cat["id"], "title": cat["title"], "coverage": coverage,
                "status": status.value, "findings_tagged": tagged,
                "checks": [{"id": r.id, "status": r.status.value} for r in mapped],
                "aspect": cat.get("aspect", ""), "not_covered": cat.get("not_covered", ""),
            })
        out.append({"id": std["id"], "title": std["title"], "categories": categories})
    return out
