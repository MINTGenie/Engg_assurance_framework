"""C/C++ adapters: cppcheck (quality/defects) and flawfinder (security, lexical)."""
from __future__ import annotations

import csv
import io
import os
import xml.etree.ElementTree as ET

from eaf.models import Finding, Severity
from eaf.runner import find_tool
from eaf.scanners.base import ScanContext, ScanNotExecuted, ScannerAdapter, ScanOutput, chunks

CPPCHECK_SEVERITY = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "style": Severity.LOW,
                     "performance": Severity.LOW, "portability": Severity.LOW,
                     "information": Severity.INFO}
CPPCHECK_IGNORED = {"missingInclude", "missingIncludeSystem", "checkersReport",
                    "unmatchedSuppression", "normalCheckLevelMaxBranches", "toomanyconfigs"}

HEADER_EXT = {".h", ".hpp", ".hh", ".hxx"}
MAX_INCLUDE_DIRS = 64


class CppcheckAdapter(ScannerAdapter):
    id = "quality.cppcheck"
    title = "C/C++ static analysis (cppcheck)"
    category = "code_quality"
    tool = "cppcheck"
    languages = ("c", "cpp")

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(notes=["Analysed without a compilation database: include paths and "
                                "preprocessor defines are unknown, so some code paths are not "
                                "checked and some findings may be configuration artefacts."])
        all_files = self.target_files(ctx)
        out.files_examined = len(all_files)
        headers = [f for f in all_files if os.path.splitext(f)[1].lower() in HEADER_EXT]
        sources = [f for f in all_files if f not in set(headers)]
        # Headers are analysed through the sources that include them. Analysing a header as
        # its own translation unit produces false "unused member" findings, so that is only
        # done for header-only scopes.
        files = sources or headers
        if not sources:
            out.notes.append("Header-only scope: headers analysed as standalone translation units.")
        include_dirs = sorted({os.path.dirname(h) for h in headers})[:MAX_INCLUDE_DIRS]
        out.notes.append(f"Include path heuristic: {len(include_dirs)} director(ies) containing "
                         "headers inside the scope were passed with -I.")
        file_list = ctx.workdir / "cppcheck-files.txt"
        file_list.write_text("\n".join(ctx.abs(f) for f in files), encoding="utf-8")
        res = ctx.run(self.id, [find_tool(self.tool), "--xml", "--xml-version=2", "--quiet",
                                "--enable=warning,style,performance,portability",
                                "--suppress=missingInclude", "--suppress=missingIncludeSystem",
                                *[f"-I{ctx.abs(d) if d else str(ctx.root)}" for d in include_dirs],
                                f"--file-list={file_list}"])
        out.evidence.append(res.evidence)
        if res.timed_out or res.exit_code != 0:
            raise ScanNotExecuted(f"cppcheck failed (exit {res.exit_code}, timeout={res.timed_out})")
        try:
            tree = ET.fromstring(res.stderr)
        except ET.ParseError as exc:
            raise ScanNotExecuted(f"cppcheck XML output could not be parsed: {exc}") from exc
        for err in tree.iter("error"):
            rule = err.get("id", "")
            if rule in CPPCHECK_IGNORED:
                continue
            loc = err.find("location")
            cwe = err.get("cwe")
            out.findings.append(Finding(
                check_id=self.id, rule_id=rule,
                severity=CPPCHECK_SEVERITY.get(err.get("severity", ""), Severity.LOW),
                message=err.get("msg", ""),
                file=ctx.rel(loc.get("file")) if loc is not None else None,
                line=int(loc.get("line", 0)) or None if loc is not None else None,
                cwe=f"CWE-{cwe}" if cwe else None))
        return out


def flawfinder_severity(level: int) -> Severity:
    if level >= 4:
        return Severity.HIGH
    if level == 3:
        return Severity.MEDIUM
    return Severity.LOW if level >= 1 else Severity.INFO


class FlawfinderAdapter(ScannerAdapter):
    id = "security.flawfinder"
    title = "C/C++ risky API usage (flawfinder)"
    category = "security"
    tool = "flawfinder"
    languages = ("c", "cpp")

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(notes=["flawfinder matches function names lexically without data-flow "
                                "analysis; expect false positives, especially at risk levels 1-2 "
                                "(reported as 'low')."])
        files = self.target_files(ctx)
        out.files_examined = len(files)
        for batch in chunks(files):
            res = ctx.run(self.id, [find_tool(self.tool), "--csv", "--dataonly", "--quiet",
                                    "--minlevel=1", *[ctx.abs(f) for f in batch]])
            out.evidence.append(res.evidence)
            if res.timed_out or res.exit_code != 0:
                raise ScanNotExecuted(f"flawfinder failed (exit {res.exit_code}): "
                                      f"{res.stderr.strip()[:300]}")
            for row in csv.DictReader(io.StringIO(res.stdout)):
                try:
                    level = int(row.get("Level") or 0)
                except ValueError:
                    continue
                cwes = (row.get("CWEs") or "").replace("!", "").split(",")[0].split("/")[0].strip()
                out.findings.append(Finding(
                    check_id=self.id, rule_id=f"{row.get('RuleId', '')}:{row.get('Name', '')}",
                    severity=flawfinder_severity(level),
                    message=f"[level {level}] {row.get('Warning', '')} {row.get('Suggestion', '')}".strip(),
                    file=ctx.rel(row.get("File", "")), line=int(row.get("Line") or 0) or None,
                    cwe=cwes or None))
        return out
