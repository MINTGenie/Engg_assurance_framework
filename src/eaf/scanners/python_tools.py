"""Python adapters: ruff (quality), bandit (security), pip-audit (dependencies)."""
from __future__ import annotations

import json
import re

from eaf.discovery import parse_requirements
from eaf.models import Finding, Severity
from eaf.runner import find_tool
from eaf.scanners.base import ScanContext, ScanNotExecuted, ScannerAdapter, ScanOutput, chunks

RUFF_RULES = "E7,E9,F,B,PLE,C901"


def ruff_severity(code: str) -> Severity:
    if not code or code == "invalid-syntax" or code.startswith(("E9", "F82", "F7")):
        return Severity.HIGH      # syntax errors, undefined names
    if code.startswith(("B", "PLE", "F5", "F6")):
        return Severity.MEDIUM    # likely bugs
    return Severity.LOW           # unused imports/variables, style, complexity


class RuffAdapter(ScannerAdapter):
    id = "quality.ruff"
    title = "Python static code quality (ruff)"
    category = "code_quality"
    tool = "ruff"
    languages = ("python",)

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(notes=[f"Rule selection: {RUFF_RULES}; repository ruff config ignored "
                                "(--isolated) for reproducibility."])
        files = self.target_files(ctx)
        out.files_examined = len(files)
        for batch in chunks(files):
            res = ctx.run(self.id, [find_tool(self.tool), "check", "--isolated", "--no-cache",
                                    "--no-fix", "--output-format", "json", "--select", RUFF_RULES,
                                    *[ctx.abs(f) for f in batch]])
            out.evidence.append(res.evidence)
            if res.timed_out or res.exit_code not in (0, 1):
                raise ScanNotExecuted(f"ruff failed (exit {res.exit_code}, timeout={res.timed_out}): "
                                      f"{res.stderr.strip()[:300]}")
            for item in json.loads(res.stdout or "[]"):
                code = item.get("code") or "invalid-syntax"
                out.findings.append(Finding(
                    check_id=self.id, rule_id=code, severity=ruff_severity(code),
                    message=item.get("message", ""), file=ctx.rel(item.get("filename", "")),
                    line=(item.get("location") or {}).get("row")))
        return out


_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")


class BanditAdapter(ScannerAdapter):
    id = "security.bandit"
    title = "Python security weaknesses (bandit)"
    category = "security"
    tool = "bandit"
    languages = ("python",)
    SKIPPED = "B101"  # assert usage: pure noise in test code

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(notes=[f"Bandit tests skipped: {self.SKIPPED} (assert)."])
        files = self.target_files(ctx)
        out.files_examined = len(files)
        sev = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
        for batch in chunks(files):
            res = ctx.run(self.id, [find_tool(self.tool), "-f", "json", "-q", "--skip", self.SKIPPED,
                                    *[ctx.abs(f) for f in batch]])
            out.evidence.append(res.evidence)
            try:
                data = json.loads(res.stdout)
            except json.JSONDecodeError as exc:
                raise ScanNotExecuted(f"bandit produced no parseable output (exit {res.exit_code}): "
                                      f"{res.stderr.strip()[:300]}") from exc
            for err in data.get("errors", []):
                out.notes.append(f"bandit could not analyse {ctx.rel(err.get('filename', '?'))}: "
                                 f"{err.get('reason', '')}")
            for r in data.get("results", []):
                rule = r.get("test_id", "")
                msg = r.get("issue_text", "")
                if rule in ("B105", "B106", "B107"):  # message echoes the hardcoded value
                    msg = _QUOTED.sub("'<redacted>'", msg)
                cwe = (r.get("issue_cwe") or {}).get("id")
                out.findings.append(Finding(
                    check_id=self.id, rule_id=rule,
                    severity=sev.get(r.get("issue_severity", "LOW"), Severity.LOW),
                    message=f"{msg} [{r.get('test_name', '')}]",
                    file=ctx.rel(r.get("filename", "")), line=r.get("line_number"),
                    cwe=f"CWE-{cwe}" if cwe else None,
                    confidence=str(r.get("issue_confidence", "")).lower() or None))
        return out


class PipAuditAdapter(ScannerAdapter):
    id = "dependencies.pip-audit"
    title = "Python dependencies: known vulnerabilities (pip-audit)"
    category = "dependencies"
    tool = "pip-audit"
    languages = ("python",)
    requires_network = True

    def _requirement_files(self, ctx: ScanContext) -> list[str]:
        return ctx.inventory.manifest_paths("requirements*.txt")

    def applicable(self, ctx: ScanContext) -> tuple[bool, str]:
        if self._requirement_files(ctx):
            return True, ""
        if any(m["ecosystem"] == "python" for m in ctx.inventory.manifests):
            return True, ""
        return False, "No Python dependency manifest in scope"

    def preflight(self, ctx: ScanContext) -> str | None:
        reason = super().preflight(ctx)
        if reason:
            return reason
        if not self._requirement_files(ctx):
            return ("Only requirements*.txt files are audited at Level 1; resolving "
                    "pyproject.toml/setup.py dependencies would require running build code")
        return None

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(notes=["Package names and versions (not source code) were sent to the "
                                "PyPI vulnerability service.",
                                "pip-audit reports no severity; all known vulnerabilities are "
                                "rated 'high'."])
        audited = 0
        for rel in self._requirement_files(ctx):
            reqs = parse_requirements((ctx.root / rel).read_text(encoding="utf-8", errors="replace"))
            if not reqs:
                continue
            unpinned = [r["name"] for r in reqs if not r["pinned"]]
            if unpinned:
                out.notes.append(f"{rel}: skipped, unpinned requirements ({', '.join(unpinned[:5])}"
                                 f"{'...' if len(unpinned) > 5 else ''}) cannot be audited without "
                                 "dependency resolution")
                continue
            res = ctx.run(self.id, [find_tool(self.tool), "-r", ctx.abs(rel), "--no-deps",
                                    "--disable-pip", "-f", "json", "--progress-spinner", "off"],
                          network=True)
            out.evidence.append(res.evidence)
            try:
                data = json.loads(res.stdout)
            except json.JSONDecodeError as exc:
                raise ScanNotExecuted(f"pip-audit failed for {rel} (exit {res.exit_code}): "
                                      f"{res.stderr.strip()[-300:]}") from exc
            audited += 1
            out.files_examined += 1
            # The advisory service returns aliases in varying order and may list one advisory
            # several times; normalise so that identical inputs give identical findings.
            merged: dict[tuple, dict] = {}
            for dep in data.get("dependencies", []):
                for v in dep.get("vulns", []):
                    entry = merged.setdefault((dep.get("name"), dep.get("version"), v.get("id", "VULN")),
                                              {"aliases": set(), "fixes": set()})
                    entry["aliases"].update(v.get("aliases", []))
                    entry["fixes"].update(v.get("fix_versions", []))
            for (name, version, vuln_id), entry in sorted(merged.items()):
                aliases = ", ".join(sorted(entry["aliases"])[:3]) or vuln_id
                fixes = ", ".join(sorted(entry["fixes"])) or "none listed"
                out.findings.append(Finding(
                    check_id=self.id, rule_id=vuln_id, severity=Severity.HIGH,
                    message=f"{name} {version} has a known vulnerability ({aliases}); "
                            f"fix versions: {fixes}", file=rel))
        if not audited:
            raise ScanNotExecuted("No fully pinned requirements file could be audited: "
                                  + "; ".join(out.notes[2:]))
        return out
