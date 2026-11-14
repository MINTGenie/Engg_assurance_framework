"""Configurable guidance packs.

A guidance pack is a versioned TOML document with three parts:

* ``[[practice]]``    engineering practices to look for (specification, documentation,
                      review process ...) together with *why* and *how* text;
* ``[[remediation]]`` fix guidance and standard references attached to scanner findings;
* ``[cwe_standards]`` CWE -> standard category mapping (e.g. OWASP Top 10).

Teams adapt guidance by writing their own pack that ``extends`` the bundled one, overriding
or disabling entries, and selecting it with ``--guidance`` or in the profile.
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
import tomllib
from importlib import resources
from pathlib import Path

from eaf.gitinfo import hardened_git
from eaf.models import Finding, Severity
from eaf.scanners.base import ScanContext, ScanNotExecuted, ScannerAdapter, ScanOutput

CONDITIONS = ("code", "api", "database", "vector", "mcp", "ai_assisted", "git")
TEXT_EXT = (".md", ".mdx", ".rst", ".txt", ".adoc", ".feature", ".yaml", ".yml", ".json", ".toml")


class GuidanceError(ValueError):
    pass


def bundled_guidance() -> dict[str, Path]:
    base = resources.files("eaf") / "data" / "guidance"
    return {p.name.removesuffix(".toml"): Path(str(p))
            for p in base.iterdir() if p.name.endswith(".toml")}


def _glob_match(rel: str, patterns: list[str]) -> bool:
    low, name = rel.lower(), rel.lower().rsplit("/", 1)[-1]
    for p in patterns:
        p = p.lower()
        if fnmatch.fnmatch(low, p) or ("/" not in p and fnmatch.fnmatch(name, p)):
            return True
    return False


def _read(path: Path, limit: int = 400_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


class PracticeCheck(ScannerAdapter):
    """One engineering practice from a guidance pack, evaluated on the file inventory."""

    category = "practices"

    def __init__(self, spec: dict, pack_id: str):
        self.spec = spec
        self.id = f"practice.{spec['id']}"
        self.title = spec.get("title", spec["id"])
        self.severity = Severity.parse(spec.get("severity", "low"))
        self.conditions = list(spec.get("applies_when", ["code"]))
        self.pack_id = pack_id

    @property
    def scanner_name(self) -> str:
        return f"eaf-guidance:{self.pack_id}"

    # -- applicability ----------------------------------------------------------------
    def applicable(self, ctx: ScanContext) -> tuple[bool, str]:
        tech = ctx.inventory.technologies
        state = {
            "code": bool(ctx.inventory.supported_languages),
            "api": bool(tech.get("api_frameworks") or tech.get("openapi_documents")),
            "database": bool(tech.get("data_stores")),
            "vector": bool(tech.get("vector_stores")),
            "mcp": bool(tech.get("mcp_packages") or tech.get("mcp_config_files")),
            # applies unless the profile explicitly says the project is conventionally developed
            "ai_assisted": ctx.profile.development_mode != "conventional",
            "git": hardened_git(ctx.root, ["rev-parse", "--is-inside-work-tree"]) is not None,
        }
        missing = [c for c in self.conditions if not state.get(c, False)]
        if missing:
            return False, "Practice applies only when: " + ", ".join(self.conditions) + \
                f" (not met: {', '.join(missing)})"
        return True, ""

    # -- evaluation -------------------------------------------------------------------
    def _guidance(self) -> str:
        parts = [self.spec.get("why", "").strip(), self.spec.get("how", "").strip()]
        return " ".join(p for p in parts if p)

    def _finding(self, rule: str, message: str, file: str | None = None) -> Finding:
        return Finding(check_id=self.id, rule_id=rule, severity=self.severity, message=message,
                       file=file, guidance=self._guidance(),
                       standards=list(self.spec.get("references", [])))

    def scan(self, ctx: ScanContext) -> ScanOutput:
        spec, out = self.spec, ScanOutput()
        files = [f.rel for f in ctx.inventory.files]
        matched = [f for f in files if _glob_match(f, spec.get("paths", []))] if spec.get("paths") else []
        out.files_examined = len(matched)

        if spec.get("paths"):
            if not matched:
                out.findings.append(self._finding(
                    "not-found", f"Not found: {self.title}. Looked for: "
                                 f"{', '.join(spec['paths'][:8])}{' ...' if len(spec['paths']) > 8 else ''}"))
                return out
            out.notes.append("Evidence: " + ", ".join(matched[:10])
                             + (f" (+{len(matched) - 10} more)" if len(matched) > 10 else ""))
            text_files = [f for f in matched if f.lower().endswith(TEXT_EXT) or "." not in f.rsplit("/", 1)[-1]]
            if spec.get("min_words"):
                words = sum(len(_read(ctx.root / f).split()) for f in text_files[:50])
                if words < int(spec["min_words"]):
                    out.findings.append(self._finding(
                        "too-thin", f"{self.title}: found, but only {words} words in "
                                    f"{len(text_files)} file(s) (expected at least {spec['min_words']})",
                        matched[0]))
            if spec.get("content_any"):
                regexes = [re.compile(r, re.I | re.M) for r in spec["content_any"]]
                if not any(r.search(_read(ctx.root / f)) for f in text_files[:50] for r in regexes):
                    out.findings.append(self._finding(
                        "content-missing", f"{self.title}: files exist but none contains "
                                           f"{spec.get('content_label', 'the expected content')}",
                        matched[0]))

        for section in spec.get("readme_sections", []):
            readmes = [f for f in files if "/" not in f and f.lower().startswith("readme")]
            if not readmes:
                out.findings.append(self._finding("no-readme", "No README at the scope root"))
                break
            text = _read(ctx.root / readmes[0])
            headings = "\n".join(ln for ln in text.splitlines()
                                 if ln.lstrip().startswith(("#", "="))
                                 or re.match(r"^[A-Z][\w /&-]{2,60}$", ln.strip()))
            out.files_examined = max(out.files_examined, 1)
            if not re.search(section["pattern"], headings, re.I | re.M):
                out.findings.append(self._finding(
                    f"readme-section:{section['name']}",
                    f"README has no section about: {section['name']}", readmes[0]))

        if spec.get("freshness"):
            self._freshness(ctx, out, files)
        return out

    def _freshness(self, ctx: ScanContext, out: ScanOutput, files: list[str]) -> None:
        cfg = spec = self.spec["freshness"]
        docs = [f for f in files if _glob_match(f, cfg.get("docs", []))]
        code = ctx.inventory.files_for(*ctx.inventory.supported_languages)
        if not docs or not code:
            out.notes.append("No documentation or no source files to compare.")
            return
        if hardened_git(ctx.root, ["rev-parse", "--is-shallow-repository"]) in (None, "true\n"):
            raise ScanNotExecuted("Shallow clone or no git history: documentation age cannot be "
                                  "compared with code age. Run on a full clone.")

        def last_commit(paths: list[str]) -> int | None:
            res = hardened_git(ctx.root, ["log", "-1", "--format=%ct", "--", *paths[:300]])
            return int(res.strip()) if res and res.strip().isdigit() else None

        t_docs, t_code = last_commit(docs), last_commit(code)
        if t_docs is None or t_code is None:
            raise ScanNotExecuted("Commit dates of documentation or code could not be determined "
                                  "(uncommitted files?)")
        lag_days = (t_code - t_docs) / 86400
        out.notes.append(f"Last documentation commit is {lag_days:.0f} day(s) "
                         f"{'older' if lag_days >= 0 else 'newer'} than the last code commit.")
        if lag_days > int(spec.get("max_lag_days", 90)):
            out.findings.append(self._finding(
                "stale-docs", f"Documentation was last changed {lag_days:.0f} days before the "
                              f"latest code change (limit: {spec.get('max_lag_days', 90)} days)"))


class GuidancePack:
    def __init__(self, doc: dict, source: str, sha256: str):
        meta = doc.get("guidance", {})
        if not meta.get("id") or not meta.get("version"):
            raise GuidanceError(f"{source}: [guidance] requires 'id' and 'version'")
        self.id, self.version = str(meta["id"]), str(meta["version"])
        self.title = str(meta.get("title", self.id))
        self.source, self.sha256 = source, sha256
        self.practices: list[dict] = list(doc.get("practice", []))
        self.remediations: list[dict] = list(doc.get("remediation", []))
        self.cwe_standards: dict[str, list[str]] = dict(doc.get("cwe_standards", {}))
        self.extends: list[str] = []
        for p in self.practices:
            self._validate_practice(p)

    def _validate_practice(self, p: dict) -> None:
        if not p.get("id"):
            raise GuidanceError(f"{self.source}: every [[practice]] needs an 'id'")
        try:
            Severity.parse(p.get("severity", "low"))
        except ValueError as exc:
            raise GuidanceError(f"{self.source}: practice {p['id']}: invalid severity") from exc
        bad = [c for c in p.get("applies_when", []) if c not in CONDITIONS]
        if bad:
            raise GuidanceError(f"{self.source}: practice {p['id']}: unknown applies_when {bad}; "
                                f"valid: {CONDITIONS}")
        if not (p.get("paths") or p.get("readme_sections") or p.get("freshness")):
            raise GuidanceError(f"{self.source}: practice {p['id']} needs 'paths', "
                                "'readme_sections' or 'freshness'")

    def merge_base(self, base: "GuidancePack", disable: list[str]) -> None:
        """Layer this pack over ``base``: same-id practices replace, others are added."""
        own = {p["id"] for p in self.practices}
        self.practices = [p for p in base.practices if p["id"] not in own] + self.practices
        self.practices = [p for p in self.practices
                          if not any(fnmatch.fnmatch(p["id"], d) for d in disable)]
        self.remediations = self.remediations + base.remediations  # own entries match first
        self.cwe_standards = {**base.cwe_standards, **self.cwe_standards}
        self.extends = [f"{base.id}@{base.version}", *base.extends]

    def describe(self) -> dict:
        return {"id": self.id, "version": self.version, "title": self.title,
                "source": self.source, "sha256": self.sha256, "extends": self.extends,
                "practices": len(self.practices), "remediation_entries": len(self.remediations)}

    def adapters(self) -> list[PracticeCheck]:
        return [PracticeCheck(p, self.id) for p in self.practices]

    def enrich(self, finding: Finding) -> None:
        """Attach fix guidance and standard references to a scanner finding."""
        for r in self.remediations:
            if fnmatch.fnmatch(finding.check_id, r.get("check", "*")) and \
                    fnmatch.fnmatchcase(finding.rule_id, r.get("rule", "*")) and \
                    (not r.get("cwe") or r["cwe"] == finding.cwe):
                if r.get("guidance"):
                    finding.guidance = r["guidance"].strip()
                for s in r.get("standards", []):
                    if s not in finding.standards:
                        finding.standards.append(s)
                break
        if finding.cwe:
            for s in [finding.cwe, *self.cwe_standards.get(finding.cwe, [])]:
                if s not in finding.standards:
                    finding.standards.append(s)


def load_guidance(name_or_path: str, _depth: int = 0) -> GuidancePack:
    bundled = bundled_guidance()
    path = bundled.get(name_or_path) or Path(name_or_path)
    if not path.is_file():
        raise GuidanceError(f"Guidance pack '{name_or_path}' not found. Bundled: {sorted(bundled)}")
    raw = path.read_bytes()
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise GuidanceError(f"Cannot parse guidance pack {path}: {exc}") from exc
    pack = GuidancePack(doc, name_or_path if name_or_path in bundled else str(path),
                        hashlib.sha256(raw).hexdigest())
    base_name = doc.get("guidance", {}).get("extends")
    if base_name:
        if _depth > 4:
            raise GuidanceError("Guidance packs are nested too deeply (extends loop?)")
        base_ref = base_name if base_name in bundled else str((path.parent / base_name).resolve())
        pack.merge_base(load_guidance(base_ref, _depth + 1),
                        [str(d) for d in doc.get("guidance", {}).get("disable", [])])
    return pack
