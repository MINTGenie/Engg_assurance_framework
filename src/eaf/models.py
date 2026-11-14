"""Core data model: statuses, severities, findings and check results."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_EXECUTED = "NOT_EXECUTED"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls(str(value).strip().lower())


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

CATEGORIES = ("code_quality", "security", "secrets", "dependencies", "hygiene", "practices")

# Assessment depths. Only depth 1 is implemented in this prototype.
DEPTHS = {
    1: "Level 1 - static source inspection (read-only)",
    2: "Level 2 - build assessment (not implemented)",
    3: "Level 3 - runtime / test assessment (not implemented)",
    4: "Level 4 - system-level assessment (not implemented)",
}
# Assessment scopes. Directory-based scopes are implemented; the others are reserved.
SCOPES = ("function", "module", "component", "repository", "multi-repository")
IMPLEMENTED_SCOPES = ("module", "component", "repository")


@dataclass
class Finding:
    check_id: str
    rule_id: str
    severity: Severity
    message: str
    file: str | None = None  # path relative to the assessed root
    line: int | None = None
    cwe: str | None = None
    confidence: str | None = None
    suppressed: bool = False
    suppression_reason: str | None = None
    guidance: str | None = None                          # how to fix / what good looks like
    standards: list[str] = field(default_factory=list)   # e.g. "OWASP-2021-A03", "CWE-89"
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.fingerprint:
            raw = "|".join(
                [self.check_id, self.rule_id, self.file or "", str(self.line or ""), self.message]
            )
            self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Evidence:
    """What was actually executed to produce a check result."""

    command: list[str]
    exit_code: int | None
    duration_s: float
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    raw_output_file: str | None = None  # relative to the report directory
    timed_out: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CheckResult:
    id: str
    title: str
    category: str
    status: Status
    scanner: str  # tool name, or "eaf-builtin"
    scanner_version: str | None = None
    reason: str = ""  # why this status (mandatory for NOT_* statuses)
    languages: list[str] = field(default_factory=list)
    files_examined: int = 0
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    thresholds: dict = field(default_factory=dict)
    duration_s: float = 0.0
    requires_network: bool = False

    def severity_counts(self, include_suppressed: bool = False) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            if f.suppressed and not include_suppressed:
                continue
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "status": self.status.value,
            "reason": self.reason,
            "scanner": self.scanner,
            "scanner_version": self.scanner_version,
            "requires_network": self.requires_network,
            "languages": self.languages,
            "files_examined": self.files_examined,
            "thresholds": self.thresholds,
            "finding_counts": self.severity_counts(),
            "suppressed_count": sum(1 for f in self.findings if f.suppressed),
            "findings": [f.to_dict() for f in self.findings],
            "evidence": [e.to_dict() for e in self.evidence],
            "notes": self.notes,
            "duration_s": round(self.duration_s, 3),
        }
