"""Built-in engineering hygiene checks (no external tool)."""
from __future__ import annotations

import json
import os

from eaf.discovery import (DEFAULT_EXCLUDED_DIRS, SUPPORTED_LANGUAGES, is_test_file,
                           parse_requirements)
from eaf.gitinfo import hardened_git
from eaf.models import Finding, Severity
from eaf.scanners.base import ScanContext, ScannerAdapter, ScanOutput

LARGE_FILE_BYTES = 5_000_000
BINARY_ARTIFACT_EXT = {".exe", ".dll", ".so", ".dylib", ".a", ".o", ".obj", ".lib", ".jar",
                       ".war", ".class", ".pyc", ".whl", ".elf", ".hex", ".bin"}


def _top_level(ctx: ScanContext, prefixes: tuple[str, ...]) -> list[str]:
    return [f.rel for f in ctx.inventory.files
            if "/" not in f.rel and f.rel.lower().startswith(prefixes)]


class _Builtin(ScannerAdapter):
    category = "hygiene"

    def finding(self, rule: str, severity: Severity, message: str, file: str | None = None) -> Finding:
        return Finding(check_id=self.id, rule_id=rule, severity=severity, message=message, file=file)


class ReadmeCheck(_Builtin):
    id = "hygiene.readme"
    title = "README present at scope root"

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(files_examined=len(ctx.inventory.files))
        if not _top_level(ctx, ("readme",)):
            out.findings.append(self.finding("missing-readme", Severity.LOW,
                                             "No README file at the root of the assessed scope"))
        return out


class LicenseCheck(_Builtin):
    id = "hygiene.license"
    title = "License / copyright notice present"

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(files_examined=len(ctx.inventory.files))
        if not _top_level(ctx, ("license", "licence", "copying", "notice")):
            out.findings.append(self.finding(
                "missing-license", Severity.LOW,
                "No LICENSE/COPYING/NOTICE file at the root of the assessed scope"))
        return out


class GitignoreCheck(_Builtin):
    id = "hygiene.gitignore"
    title = ".gitignore present"

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(files_examined=1)
        if not (ctx.root / ".gitignore").is_file():
            out.findings.append(self.finding("missing-gitignore", Severity.LOW,
                                             "No .gitignore at the root of the assessed scope"))
        return out


class TestsPresentCheck(_Builtin):
    id = "hygiene.tests-present"
    title = "Automated tests exist for detected languages"
    languages = tuple(sorted(SUPPORTED_LANGUAGES))

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(notes=["Presence only (by file/directory naming). Tests are not "
                                "executed and coverage is not measured at Level 1."])
        groups = {"python": ("python",), "c/c++": ("c", "cpp"),
                  "javascript/typescript": ("javascript", "typescript")}
        for label, langs in groups.items():
            files = ctx.inventory.files_for(*langs)
            if not files:
                continue
            out.files_examined += len(files)
            tests = [f for f in files if is_test_file(f)]
            if not tests:
                out.findings.append(self.finding(
                    f"no-tests:{label}", Severity.MEDIUM,
                    f"No test files found for {label} ({len(files)} source file(s))"))
            else:
                out.notes.append(f"{label}: {len(tests)} test file(s) / {len(files)} source file(s)")
        return out


class CiConfigCheck(_Builtin):
    id = "hygiene.ci-config"
    title = "CI pipeline configuration present"

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(files_examined=1)
        if ctx.inventory.ci:
            out.notes.append("Found: " + ", ".join(ctx.inventory.ci))
        else:
            out.findings.append(self.finding(
                "missing-ci", Severity.LOW,
                "No CI configuration found in the assessed scope (it may live in a parent "
                "directory or an external system)"))
        return out


class LargeFilesCheck(_Builtin):
    id = "hygiene.large-files"
    title = "No large files or build artefacts in source"

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(files_examined=len(ctx.inventory.files))
        for f in ctx.inventory.files:
            ext = os.path.splitext(f.rel)[1].lower()
            if ext in BINARY_ARTIFACT_EXT:
                out.findings.append(self.finding("binary-artifact", Severity.LOW,
                                                 f"Compiled/binary artefact in source tree ({ext})",
                                                 f.rel))
            elif f.size > LARGE_FILE_BYTES:
                out.findings.append(self.finding(
                    "large-file", Severity.LOW,
                    f"Large file ({f.size / 1e6:.1f} MB) in source tree", f.rel))
        return out


# Directories that hold generated or downloaded content and should not be version controlled.
GENERATED_DIRS = DEFAULT_EXCLUDED_DIRS - {".git", ".hg", ".svn", ".idea", "env", "out",
                                          "eaf-reports", "coverage", "target", "build", "dist"}
GENERATED_SUFFIXES = (".pyc", ".pyo", ".class", ".o", ".obj")


class TrackedArtifactsCheck(_Builtin):
    id = "hygiene.tracked-artifacts"
    title = "No generated files or caches under version control"

    def applicable(self, ctx: ScanContext) -> tuple[bool, str]:
        if hardened_git(ctx.root, ["rev-parse", "--is-inside-work-tree"]) is None:
            return False, "Not a git work tree"
        return True, ""

    def scan(self, ctx: ScanContext) -> ScanOutput:
        listing = hardened_git(ctx.root, ["ls-files", "-z", "--", "."])
        if listing is None:
            from eaf.scanners.base import ScanNotExecuted
            raise ScanNotExecuted("git ls-files failed")
        tracked = [p for p in listing.split("\0") if p]
        out = ScanOutput(files_examined=len(tracked), notes=[
            "Looks at files tracked by git, including directories that the other checks exclude "
            "from their scope (caches, dependency folders)."])
        by_dir: dict[str, int] = {}
        for path in tracked:
            parts = path.split("/")
            hit = next((d for d in parts[:-1] if d in GENERATED_DIRS or d.endswith(".egg-info")), None)
            if hit or path.endswith(GENERATED_SUFFIXES):
                key = "/".join(parts[:parts.index(hit) + 1]) + "/" if hit else path
                by_dir[key] = by_dir.get(key, 0) + 1
        for key, n in sorted(by_dir.items()):
            out.findings.append(self.finding(
                "tracked-generated-files", Severity.LOW,
                f"{n} generated/cache file(s) are committed under '{key}'" if key.endswith("/")
                else "Generated file is committed", key))
        return out


class DependencyPinningCheck(_Builtin):
    id = "dependencies.pinning"
    title = "Dependencies are pinned / locked"
    category = "dependencies"

    def applicable(self, ctx: ScanContext) -> tuple[bool, str]:
        if any(m["kind"] == "manifest" for m in ctx.inventory.manifests):
            return True, ""
        return False, "No dependency manifest in scope"

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(notes=["Works offline. C/C++ dependencies vendored or resolved by the "
                                "build system (CMake FetchContent, git submodules) are not analysed."])
        inv = ctx.inventory
        for rel in inv.manifest_paths("requirements*.txt"):
            out.files_examined += 1
            reqs = parse_requirements((ctx.root / rel).read_text(encoding="utf-8", errors="replace"))
            for r in reqs:
                if not r["pinned"]:
                    out.findings.append(self.finding(
                        "unpinned-python-dependency", Severity.MEDIUM,
                        f"'{r['name']}{r['spec']}' is not pinned to an exact version (==)", rel))
        npm_locks = {os.path.dirname(p) for g in ("package-lock.json", "npm-shrinkwrap.json",
                                                   "yarn.lock", "pnpm-lock.yaml", "bun.lock",
                                                   "bun.lockb")
                     for p in inv.manifest_paths(g)}
        for rel in inv.manifest_paths("package.json"):
            out.files_examined += 1
            try:
                data = json.loads((ctx.root / rel).read_text(encoding="utf-8", errors="replace"))
            except ValueError:
                out.notes.append(f"{rel}: not valid JSON")
                continue
            deps = {}
            if isinstance(data, dict):
                for key in ("dependencies", "devDependencies"):
                    deps.update(data.get(key) or {})
            if deps and os.path.dirname(rel) not in npm_locks:
                out.findings.append(self.finding(
                    "missing-npm-lockfile", Severity.MEDIUM,
                    f"{len(deps)} npm dependencies declared but no lockfile next to package.json",
                    rel))
            for name, spec in sorted(deps.items()):
                if isinstance(spec, str) and (spec in ("*", "latest", "") or
                                              spec.startswith(("http:", "git+http:"))):
                    out.findings.append(self.finding(
                        "unsafe-npm-version-spec", Severity.MEDIUM,
                        f"'{name}': '{spec}' is an unbounded or insecure version specifier", rel))
        py_locks = any(m["ecosystem"] == "python" and m["kind"] == "lockfile" for m in inv.manifests)
        for rel in inv.manifest_paths("pyproject.toml"):
            out.files_examined += 1
            has_reqs = bool(inv.manifest_paths("requirements*.txt"))
            if not py_locks and not has_reqs:
                out.notes.append(f"{rel}: no Python lockfile or pinned requirements file found; "
                                 "pyproject.toml dependency ranges are not evaluated")
        return out
