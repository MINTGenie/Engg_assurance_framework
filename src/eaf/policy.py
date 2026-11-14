"""Versioned assessment policies and policy adapters.

A policy is a TOML document that turns scanner findings into check statuses and maps
checks onto controls. Organizational policies (e.g. SWEAP) plug in either as another
TOML document for the built-in "threshold" adapter, or as a Python class registered
under the "eaf.policy_adapters" entry-point group.
"""
from __future__ import annotations

import fnmatch
import hashlib
import tomllib
from importlib import metadata, resources
from pathlib import Path

from eaf.models import CheckResult, Finding, Severity, Status


class PolicyError(ValueError):
    pass


def bundled_policies() -> dict[str, Path]:
    base = resources.files("eaf") / "data" / "policies"
    return {p.name.removesuffix(".toml"): Path(str(p))
            for p in base.iterdir() if p.name.endswith(".toml")}


class ThresholdPolicyAdapter:
    """Default adapter: severity thresholds per check, optional per-criticality overrides."""

    name = "threshold"

    def __init__(self, doc: dict, source: str, sha256: str):
        self.doc, self.source, self.sha256 = doc, source, sha256
        meta = doc.get("policy", {})
        if not meta.get("id") or not meta.get("version"):
            raise PolicyError(f"{source}: [policy] requires 'id' and 'version'")
        self.id, self.version = str(meta["id"]), str(meta["version"])
        self.title = str(meta.get("title", self.id))
        self.status = str(meta.get("status", "active"))
        for check_id in list(doc.get("checks", {})):
            self.thresholds(check_id, "standard")  # validate severities early

    def describe(self) -> dict:
        return {"id": self.id, "version": self.version, "title": self.title,
                "status": self.status, "adapter": self.name, "source": self.source,
                "sha256": self.sha256}

    def thresholds(self, check_id: str, criticality: str) -> dict:
        merged = {"fail_at": "high", "warn_at": "low"}
        crit = self.doc.get("criticality", {}).get(criticality, {})

        def lookup(table: dict) -> dict:
            """Exact check id first, then glob keys such as "practice.*"."""
            if check_id in table:
                return table[check_id]
            return next((v for k, v in table.items() if fnmatch.fnmatchcase(check_id, k)), {})

        for layer in (self.doc.get("defaults", {}), lookup(self.doc.get("checks", {})),
                      crit.get("defaults", {}), lookup(crit.get("checks", {}))):
            for key in ("fail_at", "warn_at"):
                if key in layer:
                    merged[key] = str(layer[key]).lower()
        for key, value in merged.items():
            if value != "never":
                try:
                    Severity.parse(value)
                except ValueError as exc:
                    raise PolicyError(f"{self.source}: invalid {key}={value!r} for {check_id}") from exc
        return merged

    def evaluate(self, check_id: str, findings: list[Finding], criticality: str) -> tuple[Status, str]:
        th = self.thresholds(check_id, criticality)
        active = [f for f in findings if not f.suppressed]

        def at_or_above(level: str) -> int:
            if level == "never":
                return 0
            rank = Severity.parse(level).rank
            return sum(1 for f in active if f.severity.rank >= rank)

        n_fail, n_warn = at_or_above(th["fail_at"]), at_or_above(th["warn_at"])
        if n_fail:
            return Status.FAIL, f"{n_fail} finding(s) at or above '{th['fail_at']}' severity"
        if n_warn:
            return Status.WARNING, f"{n_warn} finding(s) at or above '{th['warn_at']}' severity"
        if active:
            return Status.PASS, f"{len(active)} finding(s), all below the '{th['warn_at']}' threshold"
        suppressed = len(findings) - len(active)
        return Status.PASS, "No findings" + (f" ({suppressed} suppressed)" if suppressed else "")

    def overall(self, results: list[CheckResult]) -> tuple[Status, str]:
        by = {s: [r for r in results if r.status is s] for s in Status}
        degrade = bool(self.doc.get("defaults", {}).get("not_executed_degrades_overall", True))
        if by[Status.FAIL]:
            return Status.FAIL, f"{len(by[Status.FAIL])} check(s) failed"
        if by[Status.WARNING]:
            return Status.WARNING, f"{len(by[Status.WARNING])} check(s) raised warnings"
        if not by[Status.PASS]:
            if by[Status.NOT_EXECUTED]:
                return Status.NOT_EXECUTED, "No applicable check could be executed"
            return Status.NOT_APPLICABLE, "No check was applicable to this scope"
        if by[Status.NOT_EXECUTED] and degrade:
            return Status.WARNING, (f"All executed checks passed, but {len(by[Status.NOT_EXECUTED])} "
                                    "applicable check(s) were not executed (incomplete coverage)")
        return Status.PASS, "All executed checks passed"

    def controls(self, results: list[CheckResult]) -> list[dict]:
        by_id = {r.id: r for r in results}
        order = [Status.FAIL, Status.WARNING, Status.NOT_EXECUTED, Status.PASS,
                 Status.NOT_APPLICABLE]
        out = []
        for c in self.doc.get("controls", []):
            mapped, missing = [], []
            for pattern in c.get("checks", []):
                hits = [r for r in results if fnmatch.fnmatchcase(r.id, pattern) and r not in mapped]
                mapped += hits
                if not hits and pattern not in by_id:
                    missing.append(pattern)
            if not mapped:
                status, reason = Status.NOT_EXECUTED, (
                    "No Level 1 check is mapped to this control; it needs manual evidence "
                    "or a deeper assessment level")
            else:
                status = min((r.status for r in mapped), key=order.index)
                reason = "Worst status of mapped checks"
            out.append({"id": c.get("id", ""), "title": c.get("title", ""),
                        "status": status.value, "reason": reason,
                        "checks": [{"id": r.id, "status": r.status.value} for r in mapped],
                        "unknown_checks": missing})
        return out


def _adapters() -> dict:
    registry = {ThresholdPolicyAdapter.name: ThresholdPolicyAdapter}
    for ep in metadata.entry_points(group="eaf.policy_adapters"):
        registry[ep.name] = ep.load()
    return registry


def load_policy(name_or_path: str):
    bundled = bundled_policies()
    path = bundled.get(name_or_path) or Path(name_or_path)
    if not path.is_file():
        raise PolicyError(f"Policy '{name_or_path}' not found. Bundled: {sorted(bundled)}")
    raw = path.read_bytes()
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise PolicyError(f"Cannot parse policy {path}: {exc}") from exc
    adapter_name = doc.get("policy", {}).get("adapter", "threshold")
    adapters = _adapters()
    if adapter_name not in adapters:
        raise PolicyError(f"Policy adapter '{adapter_name}' is not installed "
                          f"(available: {sorted(adapters)})")
    source = name_or_path if name_or_path in bundled else str(path)
    return adapters[adapter_name](doc, source, hashlib.sha256(raw).hexdigest())
