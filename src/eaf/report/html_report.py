"""Self-contained HTML report (no external assets, no scripts)."""
from __future__ import annotations

from html import escape as e

STATUS_LABEL = {"PASS": "PASS", "FAIL": "FAIL", "WARNING": "WARNING",
                "NOT_APPLICABLE": "NOT APPLICABLE", "NOT_EXECUTED": "NOT EXECUTED"}
STATUS_ORDER = ["FAIL", "WARNING", "NOT_EXECUTED", "PASS", "NOT_APPLICABLE"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]
MAX_FINDINGS_SHOWN = 250

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--muted:#5b6575;--line:#dde1e7;
--pass:#1a7f37;--fail:#c62828;--warn:#b26a00;--na:#6b7280;--ne:#5b4bb7;--code:#eef0f4}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e6e9ee;--muted:#9aa4b2;
--line:#2c3440;--pass:#4cc26b;--fail:#ff6b6b;--warn:#f0a93b;--na:#9aa4b2;--ne:#a99bff;--code:#252c38}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 10px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.disclaimer{border-left:4px solid var(--warn);margin:16px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:2px 14px;margin:0}
.kv dt{color:var(--muted)}.kv dd{margin:0;overflow-wrap:anywhere}
.badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:700;
border:1.5px solid currentColor;white-space:nowrap}
.PASS{color:var(--pass)}.FAIL{color:var(--fail)}.WARNING{color:var(--warn)}
.NOT_APPLICABLE{color:var(--na)}.NOT_EXECUTED{color:var(--ne)}
.overall{font-size:26px;font-weight:800;margin:2px 0}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
code{background:var(--code);padding:1px 5px;border-radius:4px;overflow-wrap:anywhere}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:8px 0}
summary{cursor:pointer;padding:10px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
details>div{padding:0 14px 14px}
.sev{font-weight:700;text-transform:uppercase;font-size:11px}
.sev-critical,.sev-high{color:var(--fail)}.sev-medium{color:var(--warn)}.sev-low,.sev-info{color:var(--muted)}
.suppressed td{opacity:.55}
ul{margin:6px 0;padding-left:20px}
"""


def _badge(status: str) -> str:
    return f'<span class="badge {e(status)}">{e(STATUS_LABEL.get(status, status))}</span>'


def _kv(pairs: list[tuple[str, object]]) -> str:
    rows = "".join(f"<dt>{e(str(k))}</dt><dd>{v}</dd>" for k, v in pairs if v not in (None, ""))
    return f'<dl class="kv">{rows}</dl>'


def _findings_table(findings: list[dict]) -> str:
    if not findings:
        return ""
    rows = []
    for f in findings[:MAX_FINDINGS_SHOWN]:
        loc = e(f.get("file") or "-") + (f":{f['line']}" if f.get("line") else "")
        extra = " ".join(x for x in [e(f.get("cwe") or ""),
                                     f"confidence: {e(f['confidence'])}" if f.get("confidence") else ""] if x)
        supp = (f'<br><span class="muted">suppressed: {e(f.get("suppression_reason") or "")}</span>'
                if f.get("suppressed") else "")
        rows.append(
            f'<tr class="{"suppressed" if f.get("suppressed") else ""}">'
            f'<td><span class="sev sev-{e(f["severity"])}">{e(f["severity"])}</span></td>'
            f'<td><code>{e(f["rule_id"])}</code></td><td class="mono">{loc}</td>'
            f'<td>{e(f["message"])}{" <span class=muted>" + extra + "</span>" if extra else ""}{supp}</td></tr>')
    more = (f'<p class="muted">Showing {MAX_FINDINGS_SHOWN} of {len(findings)} findings; '
            'the JSON report contains all of them.</p>' if len(findings) > MAX_FINDINGS_SHOWN else "")
    return ('<div class="scroll"><table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th>'
            f'<th>Message</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>{more}')


def _check_detail(c: dict) -> str:
    counts = c["finding_counts"]
    count_txt = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts.get(s)) or "no findings"
    evidence = "".join(
        f"<li><code>{e(' '.join(ev['command']))}</code><br><span class='muted'>exit {ev['exit_code']}"
        f"{' (timed out)' if ev['timed_out'] else ''}, {ev['duration_s']}s, stdout sha256 "
        f"{e((ev['stdout_sha256'] or '')[:16])}…"
        f"{', raw output: ' + e(ev['raw_output_file']) if ev.get('raw_output_file') else ''}</span></li>"
        for ev in c["evidence"])
    notes = "".join(f"<li>{e(n)}</li>" for n in c["notes"])
    th = c.get("thresholds", {})
    meta = _kv([
        ("Result", f"{_badge(c['status'])} {e(c['reason'])}"),
        ("Scanner", f"{e(c['scanner'])} {e(c['scanner_version'] or '(version not determined)')}"),
        ("Thresholds", f"fail at ≥ {e(str(th.get('fail_at')))}, warn at ≥ {e(str(th.get('warn_at')))}"),
        ("Files examined", c["files_examined"]),
        ("Duration", f"{c['duration_s']} s"),
        ("Suppressed findings", c["suppressed_count"] or None),
    ])
    return (f'<details id="{e(c["id"])}"{" open" if c["status"] == "FAIL" else ""}><summary>{_badge(c["status"])}'
            f'<strong>{e(c["title"])}</strong><code>{e(c["id"])}</code>'
            f'<span class="muted">{e(count_txt)}</span></summary><div>{meta}'
            + (f"<h4>Notes</h4><ul>{notes}</ul>" if notes else "")
            + (f"<h4>Evidence (commands executed)</h4><ul>{evidence}</ul>" if evidence else "")
            + ("<h4>Findings</h4>" + _findings_table(c["findings"]) if c["findings"] else "")
            + "</div></details>")


def render_html(report: dict) -> str:
    a, s, inv = report["assessment"], report["summary"], report["inventory"]
    scope, git, pol, prof = a["scope"], a["scope"]["git"], a["policy"], a["profile"]
    title = prof.get("name") or scope["path"].rstrip("/").rsplit("/", 1)[-1]

    rev = "not a git repository"
    if git.get("is_git_repository"):
        rev = f"<code>{e(git.get('revision') or 'no commits')}</code> on {e(git.get('branch') or '?')}"
        if git.get("dirty"):
            rev += f" <strong class='WARNING'>+ {git.get('uncommitted_entries')} uncommitted change(s)</strong>"
        elif git.get("dirty") is False:
            rev += " (clean work tree)"

    counts = s["check_status_counts"]
    count_badges = " ".join(f"{_badge(k)} × {counts.get(k, 0)}" for k in STATUS_ORDER)
    sev = s["finding_severity_counts"]
    sev_txt = ", ".join(f"{sev.get(k, 0)} {k}" for k in SEVERITIES)

    langs = "".join(
        f"<tr><td>{e(lang)}</td><td class='num'>{d['files']}</td><td class='num'>{d['lines']}</td>"
        f"<td>{'assessed' if lang in inv['supported_languages'] else '<span class=NOT_EXECUTED>not assessed (no adapter)</span>'}</td></tr>"
        for lang, d in inv["languages"].items()) or "<tr><td colspan=4>No recognised source files</td></tr>"

    def lst(items):
        return ", ".join(e(str(i)) for i in items) or "none detected"

    checks_sorted = sorted(report["checks"], key=lambda c: (STATUS_ORDER.index(c["status"]), c["id"]))
    check_rows = "".join(
        f"<tr><td>{_badge(c['status'])}</td><td><a href='#{e(c['id'])}'>{e(c['title'])}</a><br>"
        f"<code>{e(c['id'])}</code></td><td>{e(c['category'])}</td>"
        f"<td>{e(c['scanner'])} {e(c['scanner_version'] or '')}</td>"
        + "".join(f"<td class='num'>{c['finding_counts'].get(k, 0) or ''}</td>" for k in SEVERITIES)
        + f"<td>{e(c['reason'])}</td></tr>" for c in checks_sorted)
    control_rows = "".join(
        f"<tr><td>{_badge(c['status'])}</td><td><code>{e(c['id'])}</code></td><td>{e(c['title'])}</td>"
        f"<td>{', '.join(e(x['id']) + ' (' + e(STATUS_LABEL[x['status']]) + ')' for x in c['checks']) or e(c['reason'])}</td></tr>"
        for c in report["controls"])
    placeholder = (f"<p class='WARNING'><strong>Policy status: {e(pol['status'])}.</strong> "
                   "This policy is not an approved control catalogue.</p>"
                   if pol.get("status") != "active" else "")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EAF assurance report - {e(title)}</title><style>{CSS}</style></head><body><main>
<h1>Engineering Assurance Framework – Source Assessment</h1>
<div class="muted">{e(title)} · {e(a['depth_description'])} · generated {e(a['started_utc'])}
 by eaf {e(report['tool']['version'])} (report schema {e(report['schema_version'])})</div>

<div class="card disclaimer"><strong>Scope of this result.</strong> {e(report['disclaimer'])}</div>

<div class="grid">
 <div class="card"><div class="muted">Overall result</div>
  <div class="overall {e(s['overall_status'])}">{e(STATUS_LABEL[s['overall_status']])}</div>
  <div>{e(s['overall_reason'])}</div></div>
 <div class="card"><div class="muted">Checks</div><div style="line-height:2">{count_badges}</div></div>
 <div class="card"><div class="muted">Findings (not suppressed)</div><div>{e(sev_txt)}</div>
  <div class="muted">{s['suppressed_findings']} suppressed</div></div>
</div>

<h2>Assessment scope and reproducibility</h2>
<div class="card">{_kv([
    ("Path", f"<code>{e(scope['path'])}</code>"),
    ("Scope type", e(scope["type"])),
    ("Git revision", rev),
    ("Source digest", f"<code>{e(scope['source_digest'])}</code>"),
    ("Files in scope", scope["files_in_scope"]),
    ("Tree unmodified by assessment", "yes" if scope["source_tree_unmodified"] else "<strong class='FAIL'>NO</strong>"),
    ("Policy", f"{e(pol['title'])} – <code>{e(pol['id'])}@{e(pol['version'])}</code> (sha256 {e(pol['sha256'][:16])}…)"),
    ("Network lookups", "allowed" if a["network_allowed"] else "disabled"),
    ("Results digest", f"<code>{e(s['results_digest'])}</code>"),
    ("Duration", f"{a['duration_s']} s"),
])}{placeholder}</div>

<h2>Engineering context profile</h2>
<div class="card">{_kv([
    ("Profile source", e(prof["source"])),
    ("Project / component", e(" / ".join(x for x in [prof["name"], prof["component"]] if x))),
    ("Owner", e(prof["owner"])),
    ("Criticality (strictness)", e(prof["criticality"])),
    ("Development mode", e(prof["development_mode"])),
    ("AI tools", e(", ".join(prof["ai_tools"]))),
    ("Domain", e(prof["domain"])),
    ("Lifecycle stage", e(prof["lifecycle_stage"])),
    ("Suppression rules", len(prof["suppressions"]) or None),
])}</div>

<h2>Detected technology</h2>
<div class="grid">
 <div class="card scroll"><table><thead><tr><th>Language</th><th>Files</th><th>Lines</th><th>Level 1</th></tr></thead>
  <tbody>{langs}</tbody></table></div>
 <div class="card">{_kv([
    ("Frameworks", lst(f"{f['name']} ({f['ecosystem']})" for f in inv["frameworks"])),
    ("Build systems", lst(sorted({b["system"] for b in inv["build_systems"]}))),
    ("Dependency manifests", lst(m["path"] for m in inv["dependency_manifests"])),
    ("CI configuration", lst(inv["ci_configuration"])),
    ("Excluded paths", lst(inv["excluded_paths"][:20])),
 ])}</div>
</div>

<h2>Policy controls</h2>
<div class="card scroll"><table><thead><tr><th>Status</th><th>Control</th><th>Title</th><th>Mapped checks</th></tr></thead>
<tbody>{control_rows}</tbody></table></div>

<h2>Checks</h2>
<div class="card scroll"><table><thead><tr><th>Status</th><th>Check</th><th>Category</th><th>Scanner</th>
{''.join(f'<th>{k[:4]}</th>' for k in SEVERITIES)}<th>Reason</th></tr></thead><tbody>{check_rows}</tbody></table></div>

<h2>Check details and evidence</h2>
{''.join(_check_detail(c) for c in checks_sorted)}

<h2>Limitations of this assessment</h2>
<div class="card"><ul>{''.join(f'<li>{e(x)}</li>' for x in report['limitations'])}</ul></div>
</main></body></html>
"""
