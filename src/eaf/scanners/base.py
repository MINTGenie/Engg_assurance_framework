"""Scanner adapter contract.

To add a scanner: subclass ScannerAdapter, implement scan(), and either add it to
eaf.scanners.BUILTIN_ADAPTERS or expose it through the "eaf.scanners" entry-point group.
The engine - not the adapter - decides PASS/FAIL/WARNING (via the policy) and handles
NOT_APPLICABLE / NOT_EXECUTED.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from eaf.discovery import Inventory
from eaf.models import Evidence, Finding
from eaf.profile import Profile
from eaf.runner import RunResult, build_env, find_tool, run_tool

_VERSION_RE = re.compile(r"\d+(?:\.\d+)+[\w.+-]*")


class ScanNotExecuted(Exception):
    """Raised by an adapter when the check could not be performed (-> NOT_EXECUTED)."""


@dataclass
class ScanContext:
    root: Path
    inventory: Inventory
    profile: Profile
    workdir: Path  # scratch directory outside the assessed tree
    allow_network: bool = False
    timeout: int = 300
    evidence_dir: Path | None = None
    _counter: dict = field(default_factory=dict)

    def run(self, check_id: str, cmd: list[str], *, cwd: Path | None = None,
            network: bool = False, env_extra: dict[str, str] | None = None) -> RunResult:
        n = self._counter[check_id] = self._counter.get(check_id, 0) + 1
        return run_tool(cmd, cwd=cwd or self.workdir, timeout=self.timeout,
                        allow_network=network and self.allow_network, env_extra=env_extra,
                        evidence_dir=self.evidence_dir, evidence_name=f"{check_id}-{n}")

    def abs(self, rel: str) -> str:
        return str(self.root / rel)

    def rel(self, path: str) -> str:
        try:
            return Path(path).resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path


@dataclass
class ScanOutput:
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    files_examined: int = 0


def chunks(items: list[str], size: int = 400):
    for i in range(0, len(items), size):
        yield items[i:i + size]


class ScannerAdapter:
    id: str = ""
    title: str = ""
    category: str = ""
    tool: str | None = None           # executable name; None for built-in checks
    languages: tuple[str, ...] = ()   # empty = language independent
    requires_network: bool = False
    min_depth: int = 1
    version_args: tuple[str, ...] = ("--version",)

    @property
    def scanner_name(self) -> str:
        return self.tool or "eaf-builtin"

    def target_files(self, ctx: ScanContext) -> list[str]:
        return ctx.inventory.files_for(*self.languages)

    def applicable(self, ctx: ScanContext) -> tuple[bool, str]:
        if not self.languages:
            return True, ""
        if self.target_files(ctx):
            return True, ""
        return False, f"No {'/'.join(self.languages)} source files in scope"

    def version(self, ctx: ScanContext) -> str | None:
        if not self.tool:
            from eaf import __version__
            return __version__
        exe = find_tool(self.tool)
        if not exe:
            return None
        try:
            res = subprocess.run([exe, *self.version_args], capture_output=True, text=True,
                                 timeout=30, env=build_env(False), cwd=str(ctx.workdir),
                                 stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"
        m = _VERSION_RE.search(res.stdout + " " + res.stderr)
        return m.group(0) if m else "unknown"

    def preflight(self, ctx: ScanContext) -> str | None:
        """Return a reason string if the check cannot run, else None."""
        if self.tool and not find_tool(self.tool):
            return f"Scanner '{self.tool}' is not installed or not on PATH"
        return None

    def scan(self, ctx: ScanContext) -> ScanOutput:  # pragma: no cover - interface
        raise NotImplementedError
