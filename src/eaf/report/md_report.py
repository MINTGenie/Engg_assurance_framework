"""Markdown evidence summary: a short, attachable statement of what was and was not checked."""
from __future__ import annotations

LABEL = {"PASS": "PASS", "FAIL": "FAIL", "WARNING": "WARNING",
         "NOT_APPLICABLE": "NOT APPLICABLE", "NOT_EXECUTED": "NOT EXECUTED"}
SEV = ["critical", "high", "medium", "low", "info"]


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict) -> str:
    a, s, inv = report["assessment"], report["summary"], report["inventory"]
    scope, git, pol, guid = a["scope"], a["scope"]["git"], a["policy"], a.get("guidance", {})
    checks = report["checks"]
    tech = [c for c in checks if c["category"] != "practices"]
    practices = [c for c in checks if c["category"] == "practices"]
    rev = git.get("revision") or "not a git repository"
    if git.get("dirty"):
        rev += f" (+{git.get('uncommitted_entries')} uncommitted changes: result does not correspond to a commit)"
    sev = s["finding_severity_counts"]
    L = [
        "# EAF assessment evidence summary", "",
        f"> {report['disclaimer']}", "",
        "## What was assessed", "",
        f"- **Scope:** `{scope['path']}` ({scope['type']}, {scope['files_in_scope']} files)",
        f"- **Revision:** `{rev}`",
        f"- **Source digest:** `{scope['source_digest']}`",
        f"- **When / with what:** {a['started_utc']}, eaf {report['tool']['version']}, "
        f"{a['depth_description']}",
        f"- **Policy:** `{pol['id']}@{pol['version']}` · **Guidance pack:** "
        f"`{guid.get('id')}@{guid.get('version')}` · **Criticality:** {a['profile']['criticality']}",
        f"- **Languages:** {', '.join(f'{k} ({v['lines']} lines)' for k, v in inv['languages'].items()) or 'none'}",
        f"- **Not assessed:** {', '.join(inv['unsupported_languages']) or 'no unsupported languages detected'}",
        f"- **Dependency vulnerability lookups:** {'performed' if a['network_allowed'] else 'NOT performed (network disabled)'}",
        f"- **Results digest:** `{s['results_digest']}`", "",
        "## Result", "",
        f"**Overall: {LABEL[s['overall_status']]}** – {s['overall_reason']}", "",
        "Findings (not suppressed): " + ", ".join(f"{sev.get(k, 0)} {k}" for k in SEV)
        + f"; {s['suppressed_findings']} suppressed with a recorded reason.", "",
        "## Checks performed", "",
        "| Status | Check | Tool and version | Findings c/h/m/l | Note |", "|---|---|---|---|---|",
    ]
    for c in tech:
        fc = c["finding_counts"]
        counts = "/".join(str(fc.get(k, 0)) for k in SEV[:4]) if c["status"] in ("PASS", "WARNING", "FAIL") else "–"
        L.append(f"| {LABEL[c['status']]} | {_cell(c['title'])} (`{c['id']}`) | "
                 f"{c['scanner']} {c['scanner_version'] or ''} | {counts} | {_cell(c['reason'])} |")
    if practices:
        L += ["", "## Engineering practices", "",
              "Evidence that a practice is followed (a document exists and has substance). Content is not reviewed.", "",
              "| Status | Practice | Result |", "|---|---|---|"]
        for c in practices:
            f = next((x for x in c["findings"] if not x["suppressed"]), None)
            L.append(f"| {LABEL[c['status']]} | {_cell(c['title'])} | {_cell(f['message'] if f else c['reason'])} |")
    for std in report.get("standards_coverage", []):
        L += ["", f"## {std['title']} – evidence contributed", "",
              "No category is fully covered by static inspection. \"partial\" = some checks look for instances.", "",
              "| Category | Level 1 evidence | Status | Findings | Not covered |", "|---|---|---|---|---|"]
        for c in std["categories"]:
            L.append(f"| {c['id'].rsplit('-', 1)[-1]} {_cell(c['title'])} | {c['coverage']} | "
                     f"{LABEL[c['status']] if c['coverage'] == 'partial' else '–'} | "
                     f"{c['findings_tagged'] or 0} | {_cell(c['not_covered'])} |")
    top = [(c, f) for c in checks for f in c["findings"]
           if not f["suppressed"] and f["severity"] in ("critical", "high")]
    if top:
        L += ["", "## Critical and high findings", "",
              "| Severity | Check | Rule | Location | Finding | How to fix |", "|---|---|---|---|---|---|"]
        for c, f in top[:60]:
            loc = (f.get("file") or "-") + (f":{f['line']}" if f.get("line") else "")
            L.append(f"| {f['severity']} | `{c['id']}` | `{_cell(f['rule_id'])}` | `{_cell(loc)}` | "
                     f"{_cell(f['message'])} | {_cell(f.get('guidance') or '')} |")
        if len(top) > 60:
            L.append(f"\n{len(top) - 60} further critical/high findings are in the JSON report.")
    L += ["", "## Limitations", ""] + [f"- {x}" for x in report["limitations"]]
    return "\n".join(L) + "\n"
