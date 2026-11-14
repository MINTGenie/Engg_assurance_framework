"""Assessment orchestration for Level 1 (read-only static source inspection)."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import platform
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from eaf import DISCLAIMER, REPORT_SCHEMA_VERSION, __version__
from eaf.discovery import discover, tree_digest
from eaf.gitinfo import git_info
from eaf.guidance import load_guidance
from eaf.standards import standards_coverage
from eaf.models import DEPTHS, IMPLEMENTED_SCOPES, CheckResult, Status
from eaf.policy import load_policy
from eaf.profile import Profile, load_profile
from eaf.scanners import all_adapters
from eaf.scanners.base import ScanContext, ScanNotExecuted, ScannerAdapter


class AssessmentError(Exception):
    pass


@dataclass
class Options:
    depth: int = 1
    scope: str = "repository"
    profile_path: Path | None = None
    policy: str | None = None          # overrides the profile's policy
    guidance: str | None = None        # overrides the profile's guidance pack
    allow_network: bool | None = None  # None = take from profile
    timeout: int = 300
    only: list[str] = field(default_factory=list)   # glob patterns of check ids
    skip: list[str] = field(default_factory=list)
    evidence_dir: Path | None = None   # where raw scanner output is stored
    adapters: list[ScannerAdapter] | None = None    # injection point for tests/extensions


def _selected(check_id: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(check_id, p) for p in patterns)


def _run_check(adapter: ScannerAdapter, ctx: ScanContext, options: Options, profile: Profile,
               policy, allow_network: bool, guidance=None) -> CheckResult:
    start = time.monotonic()
    result = CheckResult(id=adapter.id, title=adapter.title, category=adapter.category,
                         status=Status.NOT_EXECUTED, scanner=adapter.scanner_name,
                         languages=list(adapter.languages),
                         requires_network=adapter.requires_network,
                         thresholds=policy.thresholds(adapter.id, profile.criticality))

    def done(status: Status, reason: str) -> CheckResult:
        result.status, result.reason = status, reason
        result.duration_s = time.monotonic() - start
        return result

    applicable, why = adapter.applicable(ctx)
    if not applicable:
        return done(Status.NOT_APPLICABLE, why)
    if (options.only and not _selected(adapter.id, options.only)) or \
            _selected(adapter.id, options.skip + profile.skip_checks):
        return done(Status.NOT_EXECUTED, "Deselected by command line or profile")
    if adapter.min_depth > options.depth:
        return done(Status.NOT_EXECUTED, f"Requires assessment depth {adapter.min_depth}")
    result.scanner_version = adapter.version(ctx)
    if adapter.requires_network and not allow_network:
        return done(Status.NOT_EXECUTED,
                    "Requires a network lookup of dependency names/versions; network access "
                    "is disabled by default (enable with --allow-network)")
    blocked = adapter.preflight(ctx)
    if blocked:
        return done(Status.NOT_EXECUTED, blocked)
    try:
        output = adapter.scan(ctx)
    except ScanNotExecuted as exc:
        return done(Status.NOT_EXECUTED, str(exc))
    except Exception as exc:  # an adapter bug must not abort the whole assessment
        return done(Status.NOT_EXECUTED, f"Adapter error: {type(exc).__name__}: {exc}")

    unique = {}
    for f in output.findings:  # some tools report the same issue more than once
        unique.setdefault(f.fingerprint, f)
    output.findings = list(unique.values())
    for f in output.findings:
        if guidance is not None:
            guidance.enrich(f)
        for s in profile.suppressions:
            if s.matches(f.check_id, f.rule_id, f.file):
                f.suppressed, f.suppression_reason = True, s.reason
                break
    output.findings.sort(key=lambda f: (-f.severity.rank, f.file or "", f.line or 0, f.rule_id))
    result.findings, result.evidence = output.findings, output.evidence
    result.notes, result.files_examined = output.notes, output.files_examined
    status, reason = policy.evaluate(adapter.id, output.findings, profile.criticality)
    return done(status, reason)


def results_digest(checks: list[dict]) -> str:
    """Hash of the reproducible part of the result (statuses + findings, no timings)."""
    stable = [{"id": c["id"], "status": c["status"], "scanner_version": c["scanner_version"],
               "findings": sorted((f["fingerprint"], f["severity"], f["suppressed"])
                                  for f in c["findings"])}
              for c in sorted(checks, key=lambda c: c["id"])]
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()


def assess(path: str | Path, options: Options | None = None) -> dict:
    options = options or Options()
    if options.depth not in DEPTHS:
        raise AssessmentError(f"Unknown depth {options.depth}; valid: {sorted(DEPTHS)}")
    if options.depth != 1:
        raise AssessmentError(f"{DEPTHS[options.depth]}. Only --depth 1 is available.")
    if options.scope not in IMPLEMENTED_SCOPES:
        raise AssessmentError(f"Scope '{options.scope}' is not implemented yet; "
                              f"available: {', '.join(IMPLEMENTED_SCOPES)}")
    root = Path(path).resolve()
    if not root.is_dir():
        raise AssessmentError(f"Not a directory: {path}")

    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    profile = load_profile(options.profile_path, root)
    policy = load_policy(options.policy or profile.policy)
    guidance = load_guidance(options.guidance or profile.guidance)
    allow_network = profile.allow_network if options.allow_network is None else options.allow_network

    inventory = discover(root, profile.exclude)
    digest_before = tree_digest(root, inventory.files)
    adapters = options.adapters if options.adapters is not None else \
        [*all_adapters(), *guidance.adapters()]

    results: list[CheckResult] = []
    with tempfile.TemporaryDirectory(prefix="eaf-") as tmp:
        ctx = ScanContext(root=root, inventory=inventory, profile=profile, workdir=Path(tmp),
                          allow_network=allow_network, timeout=options.timeout,
                          evidence_dir=options.evidence_dir)
        for adapter in adapters:
            results.append(_run_check(adapter, ctx, options, profile, policy, allow_network,
                                      guidance))

    digest_after = tree_digest(root, discover(root, profile.exclude).files)
    overall, overall_reason = policy.overall(results)
    checks = [r.to_dict() for r in results]
    status_counts = {s.value: sum(1 for r in results if r.status is s) for s in Status}
    severity_totals: dict[str, int] = {}
    for r in results:
        for sev, n in r.severity_counts().items():
            severity_totals[sev] = severity_totals.get(sev, 0) + n

    limitations = [
        "Level 1 inspects source text only: nothing is built, executed or tested.",
        "A PASS reflects the configured tools and thresholds only; absence of findings is not "
        "absence of defects.",
    ]
    if inventory.unsupported_languages:
        limitations.append("Languages detected but NOT assessed by language-specific scanners: "
                           + ", ".join(inventory.unsupported_languages))
    limitations.append("Engineering-practice checks establish that a document exists and has "
                       "minimal substance. They do not judge whether it is correct, complete "
                       "or followed.")
    limitations.append("Standards coverage is partial by construction: a mapped category means "
                       "some checks look for instances of that weakness class, not that the "
                       "category is satisfied.")
    if not allow_network:
        limitations.append("Known-vulnerability lookups for dependencies were not performed "
                           "(network disabled).")
    if digest_before != digest_after:
        limitations.append("The source tree changed while it was being assessed; results may "
                           "not correspond to a single state.")

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "disclaimer": DISCLAIMER,
        "tool": {"name": "eaf", "version": __version__, "python": platform.python_version(),
                 "platform": f"{platform.system()} {platform.machine()}"},
        "assessment": {
            "started_utc": started.isoformat(timespec="seconds"),
            "duration_s": round(time.monotonic() - t0, 3),
            "depth": options.depth,
            "depth_description": DEPTHS[options.depth],
            "scope": {
                "type": options.scope,
                "path": str(root),
                "git": git_info(root),
                "source_digest": f"sha256:{digest_before}",
                "source_tree_unmodified": digest_before == digest_after,
                "files_in_scope": len(inventory.files),
            },
            "network_allowed": allow_network,
            "policy": policy.describe(),
            "guidance": guidance.describe(),
            "profile": profile.to_dict(),
        },
        "inventory": inventory.to_dict(),
        "summary": {
            "overall_status": overall.value,
            "overall_reason": overall_reason,
            "check_status_counts": status_counts,
            "finding_severity_counts": severity_totals,
            "suppressed_findings": sum(c["suppressed_count"] for c in checks),
            "results_digest": f"sha256:{results_digest(checks)}",
        },
        "controls": policy.controls(results),
        "standards_coverage": standards_coverage(results),
        "checks": checks,
        "limitations": limitations,
    }
