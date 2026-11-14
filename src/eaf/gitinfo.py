"""Git revision capture.

The revision is read directly from .git files (no git process). Dirty-state detection
invokes git with hardening flags: hooks/fsmonitor disabled and optional locks off, so the
index is not rewritten and repository-configured programs are not executed.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

_SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")


def _find_git_dir(path: Path) -> tuple[Path, Path] | None:
    for parent in [path, *path.parents]:
        git = parent / ".git"
        if git.is_dir():
            return parent, git
        if git.is_file():  # worktree / submodule: "gitdir: <path>"
            try:
                text = git.read_text(encoding="utf-8").strip()
            except OSError:
                return None
            if text.startswith("gitdir:"):
                target = (parent / text.split(":", 1)[1].strip()).resolve()
                if target.is_dir():
                    return parent, target
            return None
    return None


def _resolve_ref(git_dir: Path, ref: str) -> str | None:
    common = git_dir
    commondir = git_dir / "commondir"
    if commondir.is_file():
        common = (git_dir / commondir.read_text().strip()).resolve()
    for base in (git_dir, common):
        f = base / ref
        if f.is_file():
            value = f.read_text().strip()
            if _SHA_RE.match(value):
                return value
    packed = common / "packed-refs"
    if packed.is_file():
        for line in packed.read_text().splitlines():
            parts = line.split(" ", 1)
            if len(parts) == 2 and parts[1].strip() == ref and _SHA_RE.match(parts[0]):
                return parts[0]
    return None


def hardened_git(path: Path, args: list[str], timeout: int = 60) -> str | None:
    """Run a read-only git command with hooks, fsmonitor and index writes disabled.
    Returns stdout, or None if git is unavailable, the path is not a work tree, or it fails."""
    git = shutil.which("git")
    found = _find_git_dir(Path(path).resolve())
    if not git or not found:
        return None
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "/"),
           "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
    cmd = [git, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
           "-c", f"safe.directory={found[0]}", "-c", "core.quotePath=false",
           "-C", str(path), *args]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env,
                             stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return res.stdout if res.returncode == 0 else None


def git_info(path: Path) -> dict:
    found = _find_git_dir(path.resolve())
    if not found:
        return {"is_git_repository": False, "revision": None, "branch": None, "dirty": None,
                "note": "Not a git work tree; scope is identified by source_digest only."}
    top, git_dir = found
    info = {"is_git_repository": True, "toplevel": str(top), "revision": None,
            "branch": None, "dirty": None}
    try:
        head = (git_dir / "HEAD").read_text().strip()
    except OSError:
        head = ""
    if head.startswith("ref:"):
        ref = head.split(":", 1)[1].strip()
        info["branch"] = ref.removeprefix("refs/heads/")
        info["revision"] = _resolve_ref(git_dir, ref)
        if info["revision"] is None:
            info["note"] = "Branch has no commits yet."
    elif _SHA_RE.match(head):
        info["revision"] = head
        info["branch"] = "(detached HEAD)"

    if info["revision"]:
        out = hardened_git(path, ["status", "--porcelain", "--untracked-files=normal", "--", "."])
        if out is not None:
            info["dirty"] = bool(out.strip())
            info["uncommitted_entries"] = len(out.splitlines())
        info["shallow"] = (git_dir / "shallow").is_file()
    return info
