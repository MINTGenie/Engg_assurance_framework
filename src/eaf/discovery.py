"""Read-only inventory of a source tree: languages, frameworks, manifests, build systems.

Nothing here executes repository content. Files are only listed, stat'ed and read.
Symlinks are never followed.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv", "env",
    "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "build", "dist", "out", "target", ".eggs", ".idea", ".vscode", "eaf-reports",
    "cmake-build-debug", "cmake-build-release", ".gradle", "coverage", ".next",
}
DEFAULT_EXCLUDED_FILE_GLOBS = ["*.min.js", "*.min.css", "*.map", "*.egg-info"]

# extension -> language. "supported" languages have scanner adapters at Level 1.
LANGUAGE_BY_EXT = {
    ".py": "python", ".pyi": "python",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    # detected but not assessed in this version
    ".java": "java", ".kt": "kotlin", ".go": "go", ".rs": "rust", ".cs": "csharp",
    ".swift": "swift", ".rb": "ruby", ".php": "php", ".sh": "shell", ".bash": "shell",
    ".m": "matlab/objc", ".slx": "simulink", ".arxml": "autosar-arxml", ".scala": "scala",
}
SUPPORTED_LANGUAGES = {"python", "c", "cpp", "javascript", "typescript"}

MANIFEST_PATTERNS = {
    # filename glob -> (ecosystem, kind)
    "requirements*.txt": ("python", "manifest"),
    "pyproject.toml": ("python", "manifest"),
    "setup.py": ("python", "manifest"),
    "setup.cfg": ("python", "manifest"),
    "Pipfile": ("python", "manifest"),
    "Pipfile.lock": ("python", "lockfile"),
    "poetry.lock": ("python", "lockfile"),
    "uv.lock": ("python", "lockfile"),
    "package.json": ("npm", "manifest"),
    "package-lock.json": ("npm", "lockfile"),
    "npm-shrinkwrap.json": ("npm", "lockfile"),
    "yarn.lock": ("npm", "lockfile"),
    "pnpm-lock.yaml": ("npm", "lockfile"),
    "conanfile.txt": ("conan", "manifest"),
    "conanfile.py": ("conan", "manifest"),
    "conan.lock": ("conan", "lockfile"),
    "vcpkg.json": ("vcpkg", "manifest"),
}
BUILD_SYSTEM_PATTERNS = {
    "CMakeLists.txt": "cmake", "Makefile": "make", "GNUmakefile": "make", "makefile": "make",
    "meson.build": "meson", "BUILD.bazel": "bazel", "BUILD": "bazel", "WORKSPACE": "bazel",
    "MODULE.bazel": "bazel", "build.ninja": "ninja", "SConstruct": "scons",
    "setup.py": "setuptools", "tsconfig.json": "tsc", "webpack.config.js": "webpack",
    "vite.config.js": "vite", "vite.config.ts": "vite", "rollup.config.js": "rollup",
    "Dockerfile": "docker", "build.gradle": "gradle", "pom.xml": "maven",
    "tox.ini": "tox", "noxfile.py": "nox",
}
CI_PATHS = [".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml",
            ".circleci", ".travis.yml", "bitbucket-pipelines.yml", ".zuul.yaml"]

PY_FRAMEWORKS = {
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI", "pytest": "pytest",
    "numpy": "NumPy", "pandas": "pandas", "torch": "PyTorch", "tensorflow": "TensorFlow",
    "sqlalchemy": "SQLAlchemy", "requests": "requests", "aiohttp": "aiohttp",
    "pydantic": "pydantic", "celery": "Celery", "grpcio": "gRPC",
}
JS_FRAMEWORKS = {
    "react": "React", "vue": "Vue", "@angular/core": "Angular", "express": "Express",
    "next": "Next.js", "jest": "Jest", "mocha": "Mocha", "vitest": "Vitest",
    "electron": "Electron", "@nestjs/core": "NestJS", "svelte": "Svelte",
    "typescript": "TypeScript compiler", "webpack": "webpack", "vite": "Vite",
    "eslint": "ESLint",
}
TEST_FILE_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|unittest|gtest)(/|$)|(^|/)test_[^/]+$|_test\.[a-z]+$"
    r"|\.(test|spec)\.[cm]?[jt]sx?$|(^|/)[^/]*Test\.(cpp|cc|java)$",
    re.IGNORECASE,
)
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


@dataclass
class SourceFile:
    rel: str  # POSIX path relative to root
    size: int
    language: str | None


@dataclass
class Inventory:
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    languages: dict[str, dict] = field(default_factory=dict)  # lang -> {files, lines}
    manifests: list[dict] = field(default_factory=list)
    build_systems: list[dict] = field(default_factory=list)
    frameworks: list[dict] = field(default_factory=list)
    ci: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    skipped_symlinks: int = 0

    def files_for(self, *languages: str) -> list[str]:
        return [f.rel for f in self.files if f.language in languages]

    def has(self, *languages: str) -> bool:
        return any(lang in self.languages for lang in languages)

    def manifest_paths(self, name_glob: str) -> list[str]:
        return [m["path"] for m in self.manifests
                if fnmatch.fnmatch(os.path.basename(m["path"]), name_glob)]

    @property
    def supported_languages(self) -> list[str]:
        return sorted(x for x in self.languages if x in SUPPORTED_LANGUAGES)

    @property
    def unsupported_languages(self) -> list[str]:
        return sorted(x for x in self.languages if x not in SUPPORTED_LANGUAGES)

    def to_dict(self) -> dict:
        return {
            "file_count": len(self.files),
            "total_bytes": sum(f.size for f in self.files),
            "languages": self.languages,
            "supported_languages": self.supported_languages,
            "unsupported_languages": self.unsupported_languages,
            "frameworks": self.frameworks,
            "dependency_manifests": self.manifests,
            "build_systems": self.build_systems,
            "ci_configuration": self.ci,
            "excluded_paths": self.excluded,
            "exclude_patterns": self.exclude_patterns,
            "skipped_symlinks": self.skipped_symlinks,
        }


def _matches(rel: str, patterns: list[str]) -> bool:
    name = rel.rsplit("/", 1)[-1]
    for p in patterns:
        p = p.rstrip("/")
        if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) or rel.startswith(p + "/") \
                or fnmatch.fnmatch(rel, p + "/*"):
            return True
    return False


def _count_lines(path: Path) -> int:
    try:
        with open(path, "rb") as fh:
            return sum(chunk.count(b"\n") for chunk in iter(lambda: fh.read(1 << 16), b""))
    except OSError:
        return 0


def discover(root: Path, extra_excludes: list[str] | None = None) -> Inventory:
    root = root.resolve()
    patterns = list(DEFAULT_EXCLUDED_FILE_GLOBS) + list(extra_excludes or [])
    inv = Inventory(root=root, exclude_patterns=sorted(DEFAULT_EXCLUDED_DIRS) + patterns)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        kept = []
        for d in sorted(dirnames):
            rel = f"{rel_dir}/{d}" if rel_dir else d
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                inv.skipped_symlinks += 1
            elif d in DEFAULT_EXCLUDED_DIRS or d.endswith(".egg-info") or _matches(rel, patterns):
                inv.excluded.append(rel + "/")
            else:
                kept.append(d)
        dirnames[:] = kept
        for name in sorted(filenames):
            rel = f"{rel_dir}/{name}" if rel_dir else name
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                inv.skipped_symlinks += 1
                continue
            if _matches(rel, patterns):
                inv.excluded.append(rel)
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            lang = LANGUAGE_BY_EXT.get(os.path.splitext(name)[1].lower())
            inv.files.append(SourceFile(rel=rel, size=size, language=lang))
            if lang:
                entry = inv.languages.setdefault(lang, {"files": 0, "lines": 0})
                entry["files"] += 1
                entry["lines"] += _count_lines(Path(full))
            for glob, (eco, kind) in MANIFEST_PATTERNS.items():
                if fnmatch.fnmatch(name, glob):
                    inv.manifests.append({"path": rel, "ecosystem": eco, "kind": kind})
                    break
            if name in BUILD_SYSTEM_PATTERNS:
                inv.build_systems.append({"system": BUILD_SYSTEM_PATTERNS[name], "path": rel})

    for ci in CI_PATHS:
        if (root / ci).exists():
            inv.ci.append(ci)
    _detect_build_backends(inv)
    _detect_frameworks(inv)
    inv.languages = dict(sorted(inv.languages.items()))
    return inv


def _read_text(path: Path, limit: int = 2_000_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def parse_requirements(text: str) -> list[dict]:
    """Minimal requirements.txt parser: name, raw spec, whether pinned with ==."""
    out = []
    for raw in text.splitlines():
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("#", "-r", "-c", "--", "-e", "-f", "-i")):
            continue
        m = _REQ_NAME_RE.match(line)
        if not m:
            continue
        spec = line[m.end():].split(";")[0].strip()
        spec = re.sub(r"^\[[^\]]*\]", "", spec).strip()
        out.append({"name": m.group(1).lower(), "spec": spec,
                    "pinned": spec.startswith("==") and "*" not in spec})
    return out


def _detect_build_backends(inv: Inventory) -> None:
    for rel in inv.manifest_paths("pyproject.toml"):
        try:
            data = tomllib.loads(_read_text(inv.root / rel))
        except tomllib.TOMLDecodeError:
            continue
        backend = data.get("build-system", {}).get("build-backend")
        if backend:
            inv.build_systems.append({"system": f"python:{backend}", "path": rel})
    for rel in inv.manifest_paths("package.json"):
        try:
            data = json.loads(_read_text(inv.root / rel))
        except (json.JSONDecodeError, ValueError):
            continue
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if isinstance(scripts, dict) and scripts:
            inv.build_systems.append(
                {"system": "npm-scripts", "path": rel, "scripts": sorted(scripts)})


def _detect_frameworks(inv: Inventory) -> None:
    found: dict[tuple[str, str], str] = {}

    def add(name: str, ecosystem: str, source: str) -> None:
        found.setdefault((name, ecosystem), source)

    for rel in inv.manifest_paths("requirements*.txt"):
        for req in parse_requirements(_read_text(inv.root / rel)):
            if req["name"] in PY_FRAMEWORKS:
                add(PY_FRAMEWORKS[req["name"]], "python", rel)
    for rel in inv.manifest_paths("pyproject.toml"):
        try:
            data = tomllib.loads(_read_text(inv.root / rel))
        except tomllib.TOMLDecodeError:
            continue
        deps = list(data.get("project", {}).get("dependencies", []) or [])
        for extra in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
            deps += list(extra or [])
        deps += list((data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}))
        for dep in deps:
            m = _REQ_NAME_RE.match(str(dep))
            if m and m.group(1).lower() in PY_FRAMEWORKS:
                add(PY_FRAMEWORKS[m.group(1).lower()], "python", rel)
    for rel in inv.manifest_paths("package.json"):
        try:
            data = json.loads(_read_text(inv.root / rel))
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            for dep in (data.get(key) or {}):
                if dep in JS_FRAMEWORKS:
                    add(JS_FRAMEWORKS[dep], "npm", rel)
    for bs in inv.build_systems:
        if bs["system"] == "cmake":
            text = _read_text(inv.root / bs["path"])
            for m in re.finditer(r"find_package\s*\(\s*([A-Za-z0-9_]+)", text):
                add(m.group(1), "cmake", bs["path"])
    inv.frameworks = [{"name": n, "ecosystem": e, "detected_in": s}
                      for (n, e), s in sorted(found.items())]


def is_test_file(rel: str) -> bool:
    return bool(TEST_FILE_RE.search(rel))


def tree_digest(root: Path, files: list[SourceFile]) -> str:
    """SHA-256 over (path, content hash) of every in-scope file. Identifies exactly what
    was assessed and lets the engine verify the tree was not modified by the assessment."""
    h = hashlib.sha256()
    for f in sorted(files, key=lambda x: x.rel):
        fh_hash = hashlib.sha256()
        try:
            with open(root / f.rel, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 16), b""):
                    fh_hash.update(chunk)
        except OSError:
            fh_hash.update(b"<unreadable>")
        h.update(f.rel.encode("utf-8") + b"\0" + fh_hash.digest())
    return h.hexdigest()
