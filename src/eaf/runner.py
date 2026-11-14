"""Subprocess execution for scanner tools.

Rules enforced here:
* argv lists only, never a shell;
* a hard timeout;
* tools that do not need the network get an environment without proxy settings;
* stdout/stderr are hashed and optionally stored as raw evidence.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from eaf.models import Evidence

_PROXY_VARS = {"http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy"}
_MAX_CMD_ARGS_IN_REPORT = 12


@dataclass
class RunResult:
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    evidence: Evidence


def find_tool(name: str) -> str | None:
    """Locate an executable on PATH or next to the running interpreter (venv installs)."""
    found = shutil.which(name)
    if found:
        return found
    candidate = Path(sys.executable).parent / name
    return str(candidate) if candidate.is_file() and os.access(candidate, os.X_OK) else None


def build_env(allow_network: bool, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    if not allow_network:
        env = {k: v for k, v in env.items() if k.lower() not in _PROXY_VARS}
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "NO_COLOR": "1", "CI": "1",
                "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off",
                "DO_NOT_TRACK": "1"})
    env.update(extra or {})
    return env


def _abbreviate(cmd: list[str]) -> list[str]:
    if len(cmd) <= _MAX_CMD_ARGS_IN_REPORT:
        return cmd
    return cmd[:_MAX_CMD_ARGS_IN_REPORT] + [f"... (+{len(cmd) - _MAX_CMD_ARGS_IN_REPORT} more args)"]


def run_tool(cmd: list[str], *, cwd: Path, timeout: int, allow_network: bool = False,
             env_extra: dict[str, str] | None = None, evidence_dir: Path | None = None,
             evidence_name: str | None = None) -> RunResult:
    start = time.monotonic()
    timed_out, exit_code = False, None
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, timeout=timeout,
                              env=build_env(allow_network, env_extra), shell=False,
                              stdin=subprocess.DEVNULL)
        out, err, exit_code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        out, err, timed_out = exc.stdout or b"", exc.stderr or b"", True
    duration = time.monotonic() - start

    raw_file = None
    if evidence_dir is not None and evidence_name:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        target = evidence_dir / f"{evidence_name}.txt"
        target.write_bytes(b"$ " + " ".join(cmd).encode() + b"\n--- stdout ---\n" + out
                           + b"\n--- stderr ---\n" + err)
        raw_file = f"{evidence_dir.name}/{target.name}"
    evidence = Evidence(command=_abbreviate(cmd), exit_code=exit_code,
                        duration_s=round(duration, 3),
                        stdout_sha256=hashlib.sha256(out).hexdigest(),
                        stderr_sha256=hashlib.sha256(err).hexdigest(),
                        raw_output_file=raw_file, timed_out=timed_out)
    return RunResult(out.decode("utf-8", "replace"), err.decode("utf-8", "replace"),
                     exit_code, timed_out, evidence)
