"""JavaScript/TypeScript adapters: ESLint (quality) and npm audit (dependencies)."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from functools import lru_cache
from importlib import resources
from pathlib import Path

from eaf.models import Finding, Severity
from eaf.runner import build_env, find_tool
from eaf.scanners.base import ScanContext, ScanNotExecuted, ScannerAdapter, ScanOutput, chunks

_ESM_SYNTAX = re.compile(r"^\s*(import\s*[\w{*'\"]|export\s+[\w{*])", re.MULTILINE)
_MISSING_RULE = re.compile(r"^Definition for rule '.*' was not found")


def is_es_module(path: Path) -> bool:
    """True if a .js/.jsx file uses static import/export. ESLint cannot detect this itself;
    parsing CommonJS as a module (strict mode) produces false parse errors."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return bool(_ESM_SYNTAX.search(fh.read(200_000)))
    except OSError:
        return False


ESLINT_HIGH_RULES = {"no-eval", "no-implied-eval", "no-new-func", "no-script-url"}
TS_PARSER = "@typescript-eslint/parser"


def eslint_config_path() -> Path:
    return Path(str(resources.files("eaf") / "data" / "eslint.config.cjs"))


@lru_cache(maxsize=1)
def node_path() -> str:
    """NODE_PATH used to resolve EAF's ESLint parser: $EAF_NODE_PATH, else global npm root."""
    parts = [p for p in os.environ.get("EAF_NODE_PATH", "").split(os.pathsep) if p]
    npm = find_tool("npm")
    if npm:
        try:
            res = subprocess.run([npm, "root", "-g"], capture_output=True, text=True, timeout=30,
                                 env=build_env(False), stdin=subprocess.DEVNULL, cwd="/")
            if res.returncode == 0 and res.stdout.strip():
                parts.append(res.stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            pass
    return os.pathsep.join(parts)


@lru_cache(maxsize=1)
def ts_parser_available() -> bool:
    node = find_tool("node")
    if not node:
        return False
    try:
        res = subprocess.run([node, "-e", f"require.resolve('{TS_PARSER}')"], capture_output=True,
                             timeout=30, env=build_env(False, {"NODE_PATH": node_path()}),
                             stdin=subprocess.DEVNULL, cwd="/")
        return res.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class _EslintAdapter(ScannerAdapter):
    category = "code_quality"
    tool = "eslint"
    lang_mode = "js"

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(notes=["EAF-owned config with core ESLint rules only; the repository's "
                                "ESLint config and plugins are not loaded (no-undef is disabled "
                                "because runtime globals are unknown)."])
        files = self.target_files(ctx)
        out.files_examined = len(files)
        groups: dict[str, list[str]] = {"module": [], "commonjs": []}
        for f in files:
            plain_js = f.lower().endswith((".js", ".jsx"))
            groups["commonjs" if plain_js and not is_es_module(ctx.root / f) else "module"].append(f)
        missing_rules = 0
        batches = [(kind, b) for kind, group in groups.items() for b in chunks(group, 300)]
        for source_type, batch in batches:
            env = {"EAF_ESLINT_LANG": self.lang_mode, "NODE_PATH": node_path(),
                   "EAF_ESLINT_SOURCE_TYPE": source_type}
            # ESLint only lints files below its working directory, so cwd is the assessed root.
            # It does not write there: no cache, no fix, config lookup disabled.
            res = ctx.run(self.id, [find_tool(self.tool), "--no-config-lookup",
                                    "-c", str(eslint_config_path()), "--format", "json",
                                    "--no-error-on-unmatched-pattern", "--no-warn-ignored",
                                    *batch], cwd=ctx.root, env_extra=env)
            out.evidence.append(res.evidence)
            if res.timed_out or res.exit_code not in (0, 1):
                raise ScanNotExecuted(f"eslint failed (exit {res.exit_code}, "
                                      f"timeout={res.timed_out}): {res.stderr.strip()[:300]}")
            try:
                data = json.loads(res.stdout)
            except json.JSONDecodeError as exc:
                raise ScanNotExecuted(f"eslint output could not be parsed: {exc}") from exc
            for entry in data:
                rel = ctx.rel(entry.get("filePath", ""))
                for m in entry.get("messages", []):
                    rule = m.get("ruleId")
                    if m.get("fatal"):
                        rule, sev = "parse-error", Severity.HIGH
                    elif rule is None:
                        out.notes.append(f"{rel}: {m.get('message', '')}")
                        continue
                    elif _MISSING_RULE.match(m.get("message", "")):
                        missing_rules += 1  # inline directive for a plugin EAF does not load
                        continue
                    elif rule in ESLINT_HIGH_RULES:
                        sev = Severity.HIGH
                    else:
                        sev = Severity.MEDIUM if m.get("severity") == 2 else Severity.LOW
                    out.findings.append(Finding(check_id=self.id, rule_id=rule, severity=sev,
                                                message=m.get("message", ""), file=rel,
                                                line=m.get("line")))
        if missing_rules:
            out.notes.append(f"{missing_rules} inline directive(s) reference plugin rules that "
                             "EAF does not load; ignored.")
        out.notes.append("Inline 'eslint-disable' comments in the source are honoured.")
        return out


class EslintJsAdapter(_EslintAdapter):
    id = "quality.eslint-js"
    title = "JavaScript static code quality (ESLint core rules)"
    languages = ("javascript",)
    lang_mode = "js"


class EslintTsAdapter(_EslintAdapter):
    id = "quality.eslint-ts"
    title = "TypeScript static code quality (ESLint core rules)"
    languages = ("typescript",)
    lang_mode = "ts"

    def preflight(self, ctx: ScanContext) -> str | None:
        reason = super().preflight(ctx)
        if reason:
            return reason
        if not ts_parser_available():
            return (f"'{TS_PARSER}' is not resolvable (install it globally with npm or set "
                    "EAF_NODE_PATH); TypeScript files were not linted")
        return None

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = super().scan(ctx)
        out.notes.append("Syntax-level rules only: no type-aware rules, no tsc type check.")
        return out


NPM_SEVERITY = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "moderate": Severity.MEDIUM,
                "low": Severity.LOW, "info": Severity.INFO}


class NpmAuditAdapter(ScannerAdapter):
    id = "dependencies.npm-audit"
    title = "npm dependencies: known vulnerabilities (npm audit)"
    category = "dependencies"
    tool = "npm"
    requires_network = True

    def applicable(self, ctx: ScanContext) -> tuple[bool, str]:
        if ctx.inventory.manifest_paths("package.json"):
            return True, ""
        return False, "No package.json in scope"

    def _lock_dirs(self, ctx: ScanContext) -> list[str]:
        dirs = []
        for lock in ctx.inventory.manifest_paths("package-lock.json") + \
                ctx.inventory.manifest_paths("npm-shrinkwrap.json"):
            d = os.path.dirname(lock)
            if (ctx.root / d / "package.json").is_file() and d not in dirs:
                dirs.append(d)
        return dirs

    def preflight(self, ctx: ScanContext) -> str | None:
        reason = super().preflight(ctx)
        if reason:
            return reason
        if not self._lock_dirs(ctx):
            return ("No package-lock.json next to package.json; auditing would require "
                    "dependency resolution (yarn/pnpm lockfiles are not supported yet)")
        return None

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(notes=["The dependency tree (package names and versions, not source "
                                "code) was sent to the npm registry audit endpoint."])
        for i, d in enumerate(self._lock_dirs(ctx)):
            # Audit a copy so the repository's .npmrc and lifecycle scripts are never involved.
            tmp = ctx.workdir / f"npm-audit-{i}"
            tmp.mkdir()
            for name in ("package.json", "package-lock.json", "npm-shrinkwrap.json"):
                src = ctx.root / d / name
                if src.is_file() and not src.is_symlink():
                    shutil.copyfile(src, tmp / name)
            res = ctx.run(self.id, [find_tool(self.tool), "audit", "--package-lock-only",
                                    "--ignore-scripts", "--json"], cwd=tmp, network=True)
            out.evidence.append(res.evidence)
            try:
                data = json.loads(res.stdout)
            except json.JSONDecodeError as exc:
                raise ScanNotExecuted(f"npm audit produced no JSON (exit {res.exit_code}): "
                                      f"{res.stderr.strip()[-300:]}") from exc
            if "error" in data:
                err = data["error"]
                raise ScanNotExecuted(f"npm audit failed: {err.get('code')} {err.get('summary', '')}")
            out.files_examined += 1
            lock_rel = os.path.join(d, "package-lock.json") if d else "package-lock.json"
            for name, v in sorted((data.get("vulnerabilities") or {}).items()):
                advisories = [x for x in v.get("via", []) if isinstance(x, dict)]
                via_pkgs = [x for x in v.get("via", []) if isinstance(x, str)]
                detail = "; ".join(a.get("title", "") for a in advisories[:3]) or \
                    f"vulnerable through {', '.join(via_pkgs[:3])}"
                rule = next((a.get("url", "").rsplit("/", 1)[-1] for a in advisories
                             if a.get("url")), f"npm:{name}")
                out.findings.append(Finding(
                    check_id=self.id, rule_id=rule,
                    severity=NPM_SEVERITY.get(v.get("severity", "low"), Severity.LOW),
                    message=f"{name} ({v.get('range', '?')}): {detail}"
                            f"{'' if v.get('isDirect') else ' [transitive]'}",
                    file=lock_rel))
        return out
