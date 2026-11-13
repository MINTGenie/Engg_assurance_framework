"""Engineering context profile: who/what is being assessed and how strictly."""
from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path

CRITICALITY_LEVELS = ("prototype", "standard", "elevated")
DEVELOPMENT_MODES = ("ai-assisted", "conventional", "mixed", "unknown")
PROFILE_FILENAMES = ("eaf-profile.toml", ".eaf/profile.toml")


class ProfileError(ValueError):
    pass


@dataclass
class Suppression:
    check: str
    reason: str
    rule: str = "*"
    path: str = "*"

    def matches(self, check_id: str, rule_id: str, file: str | None) -> bool:
        return (fnmatch.fnmatch(check_id, self.check)
                and fnmatch.fnmatch(rule_id, self.rule)
                and fnmatch.fnmatch(file or "", self.path))


@dataclass
class Profile:
    source: str = "built-in defaults"
    # [project]
    name: str = ""
    component: str = ""
    owner: str = ""
    # [context]
    criticality: str = "standard"
    development_mode: str = "unknown"
    ai_tools: list[str] = field(default_factory=list)
    domain: str = ""
    lifecycle_stage: str = ""
    notes: str = ""
    # [assessment]
    policy: str = "eaf-baseline"
    exclude: list[str] = field(default_factory=list)
    skip_checks: list[str] = field(default_factory=list)
    allow_network: bool = False
    suppressions: list[Suppression] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def load_profile(path: Path | None, root: Path | None = None) -> Profile:
    """Load an explicit profile, or auto-discover one in the assessed root."""
    if path is None and root is not None:
        for name in PROFILE_FILENAMES:
            candidate = root / name
            if candidate.is_file() and not candidate.is_symlink():
                path = candidate
                break
    if path is None:
        return Profile()
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProfileError(f"Cannot read profile {path}: {exc}") from exc

    project, context = data.get("project", {}), data.get("context", {})
    assessment = data.get("assessment", {})
    p = Profile(source=str(path))
    p.name = str(project.get("name", ""))
    p.component = str(project.get("component", ""))
    p.owner = str(project.get("owner", ""))
    p.criticality = str(context.get("criticality", p.criticality))
    p.development_mode = str(context.get("development_mode", p.development_mode))
    p.ai_tools = [str(x) for x in context.get("ai_tools", [])]
    p.domain = str(context.get("domain", ""))
    p.lifecycle_stage = str(context.get("lifecycle_stage", ""))
    p.notes = str(context.get("notes", ""))
    p.policy = str(assessment.get("policy", p.policy))
    p.exclude = [str(x) for x in assessment.get("exclude", [])]
    p.skip_checks = [str(x) for x in assessment.get("skip_checks", [])]
    p.allow_network = bool(assessment.get("allow_network", False))

    if p.criticality not in CRITICALITY_LEVELS:
        raise ProfileError(f"context.criticality must be one of {CRITICALITY_LEVELS}")
    if p.development_mode not in DEVELOPMENT_MODES:
        raise ProfileError(f"context.development_mode must be one of {DEVELOPMENT_MODES}")
    for i, s in enumerate(data.get("suppressions", [])):
        if not s.get("check") or not str(s.get("reason", "")).strip():
            raise ProfileError(f"suppressions[{i}] requires both 'check' and a 'reason'")
        p.suppressions.append(Suppression(check=str(s["check"]), reason=str(s["reason"]),
                                          rule=str(s.get("rule", "*")),
                                          path=str(s.get("path", "*"))))
    return p


PROFILE_TEMPLATE = '''\
# EAF engineering context profile.
# Place as "eaf-profile.toml" in the assessed directory, or pass with --profile.

[project]
name = "my-component"
component = ""          # e.g. function cluster / module name
owner = ""              # team or responsible engineer

[context]
# How strict the policy thresholds are: "prototype" | "standard" | "elevated".
# This is an engineering strictness knob, NOT a safety integrity level (ASIL) claim.
criticality = "standard"
# "ai-assisted" | "conventional" | "mixed" | "unknown"
development_mode = "unknown"
ai_tools = []           # e.g. ["GitHub Copilot"]
domain = ""             # e.g. "sdv-middleware", "tooling", "backend"
lifecycle_stage = ""    # e.g. "prototype", "series-development"
notes = ""

[assessment]
policy = "eaf-baseline"     # bundled policy id or path to a policy .toml
exclude = []                # extra path globs to leave out, e.g. ["third_party/*"]
skip_checks = []            # check ids to skip (reported as NOT_EXECUTED)
allow_network = false       # dependency-vulnerability lookups send package names+versions out

# Suppress a finding only with a documented reason. Suppressed findings stay in the report.
# [[suppressions]]
# check = "security.bandit"
# rule = "B404"
# path = "tools/*"
# reason = "subprocess use reviewed: fixed argv, no shell, see review #123"
'''
