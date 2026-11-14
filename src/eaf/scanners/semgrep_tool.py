"""Semgrep adapter with EAF's bundled, locally stored rule set (no registry access)."""
from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from eaf.models import Finding, Severity
from eaf.runner import find_tool
from eaf.scanners.base import ScanContext, ScanNotExecuted, ScannerAdapter, ScanOutput, chunks

SEVERITY = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW,
            "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW}
CANARY = "import requests\nrequests.get('https://example.invalid', verify=False)\n"


def rules_path() -> Path:
    return Path(str(resources.files("eaf") / "data" / "semgrep" / "eaf-rules.yml"))


class SemgrepAdapter(ScannerAdapter):
    id = "security.semgrep"
    title = "API, MCP, vector-store and web security patterns (semgrep, EAF rules)"
    category = "security"
    tool = "semgrep"
    languages = ("python", "javascript", "typescript")

    def _run(self, ctx: ScanContext, targets: list[str], cwd: Path):
        res = ctx.run(self.id, [find_tool(self.tool), "scan", "--config", str(rules_path()),
                                "--json", "--metrics=off", "--disable-version-check", "--quiet",
                                "--no-git-ignore", "--timeout", "30", *targets], cwd=cwd,
                      env_extra={"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"})
        try:
            return res, json.loads(res.stdout)
        except json.JSONDecodeError as exc:
            raise ScanNotExecuted(f"semgrep produced no JSON (exit {res.exit_code}, "
                                  f"timeout={res.timed_out}): {res.stderr.strip()[-300:]}") from exc

    def scan(self, ctx: ScanContext) -> ScanOutput:
        files = self.target_files(ctx)
        out = ScanOutput(files_examined=len(files), notes=[
            "Bundled EAF rule file only; no rules are downloaded and metrics are off.",
            "Pattern matching within a single file: no cross-file data flow.",
            "Inline 'nosemgrep' comments in the source are honoured."])
        # self-test: a scanner that silently finds nothing must not be reported as PASS
        (ctx.workdir / "eaf_semgrep_canary.py").write_text(CANARY, encoding="utf-8")
        res, data = self._run(ctx, ["eaf_semgrep_canary.py"], ctx.workdir)
        out.evidence.append(res.evidence)
        if not data.get("results"):
            raise ScanNotExecuted("semgrep self-test failed: a planted canary was not detected "
                                  f"({'; '.join(str(e.get('message', e))[:120] for e in data.get('errors', [])[:2])})")
        out.notes.append("Scanner self-test passed (planted canary was detected).")

        scanned: set[str] = set()
        for batch in chunks(files, 300):
            # Relative paths with cwd = assessed root: semgrep applies ignore rules by path.
            res, data = self._run(ctx, batch, ctx.root)
            out.evidence.append(res.evidence)
            scanned.update((data.get("paths") or {}).get("scanned", []))
            for err in data.get("errors", [])[:5]:
                out.notes.append(f"semgrep: {str(err.get('message', err))[:160]}")
            for r in data.get("results", []):
                extra, meta = r.get("extra", {}), r.get("extra", {}).get("metadata", {})
                out.findings.append(Finding(
                    check_id=self.id, rule_id=r.get("check_id", "").rsplit(".eaf.", 1)[-1].removeprefix("eaf."),
                    severity=SEVERITY.get(str(extra.get("severity", "INFO")).upper(), Severity.LOW),
                    message=extra.get("message", ""), file=ctx.rel(str(ctx.root / r.get("path", ""))),
                    line=(r.get("start") or {}).get("line"), cwe=meta.get("cwe"),
                    guidance=meta.get("guidance"), standards=list(meta.get("standards", []))))
        skipped = len(files) - len(scanned)
        if skipped > 0:
            out.notes.append(f"{skipped} of {len(files)} file(s) were not scanned by semgrep "
                             "(ignored by its path rules, too large, or unparseable).")
            if not scanned:
                raise ScanNotExecuted("semgrep scanned none of the target files")
        return out
