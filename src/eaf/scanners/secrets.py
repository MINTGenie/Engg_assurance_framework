"""Secret detection: detect-secrets (content) and a built-in sensitive-file check."""
from __future__ import annotations

import fnmatch
import json

from eaf.models import Finding, Severity
from eaf.runner import find_tool
from eaf.scanners.base import ScanContext, ScanNotExecuted, ScannerAdapter, ScanOutput, chunks

LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
             "poetry.lock", "Pipfile.lock", "uv.lock", "Cargo.lock", "go.sum", "conan.lock"}
MAX_SECRET_SCAN_BYTES = 1_000_000
# Lower-confidence detectors (entropy / keyword heuristics) are rated medium, not high.
HEURISTIC_TYPES = ("High Entropy", "Secret Keyword")


class DetectSecretsAdapter(ScannerAdapter):
    id = "secrets.detect-secrets"
    title = "Hardcoded secrets in file contents (detect-secrets)"
    category = "secrets"
    tool = "detect-secrets"

    def target_files(self, ctx: ScanContext) -> list[str]:
        return [f.rel for f in ctx.inventory.files
                if f.size <= MAX_SECRET_SCAN_BYTES and f.rel.rsplit("/", 1)[-1] not in LOCKFILES]

    def scan(self, ctx: ScanContext) -> ScanOutput:
        files = self.target_files(ctx)
        skipped = len(ctx.inventory.files) - len(files)
        out = ScanOutput(files_examined=len(files), notes=[
            "Working tree only; git history is not scanned.",
            "Secret values are never written to the report (only type, file and line).",
            "Online secret verification is disabled (--no-verify)."])
        if skipped:
            out.notes.append(f"{skipped} file(s) skipped (lockfiles or larger than "
                             f"{MAX_SECRET_SCAN_BYTES} bytes).")
        self._self_test(ctx, out)
        for batch in chunks(files):
            # detect-secrets silently ignores paths outside its working directory, so it runs
            # in the assessed root with relative paths. It only reads files.
            res = ctx.run(self.id, [find_tool(self.tool), "scan", "--no-verify", *batch],
                          cwd=ctx.root, env_extra={"GIT_OPTIONAL_LOCKS": "0"})
            out.evidence.append(res.evidence)
            try:
                data = json.loads(res.stdout)
            except json.JSONDecodeError as exc:
                raise ScanNotExecuted(f"detect-secrets failed (exit {res.exit_code}): "
                                      f"{res.stderr.strip()[-300:]}") from exc
            for filename, hits in sorted((data.get("results") or {}).items()):
                for hit in hits:
                    kind = hit.get("type", "Secret")
                    heuristic = any(t in kind for t in HEURISTIC_TYPES)
                    out.findings.append(Finding(
                        check_id=self.id, rule_id=kind.replace(" ", "-"),
                        severity=Severity.MEDIUM if heuristic else Severity.HIGH,
                        message=f"Possible secret: {kind}",
                        file=ctx.rel(filename), line=hit.get("line_number"),
                        confidence="heuristic" if heuristic else "pattern"))
        return out


CANARY = 'aws_access_key_id = "AKIA' + "QWERTYUIOPASDFGH" + '"\n'


def _self_test(self, ctx: ScanContext, out: ScanOutput) -> None:
    """Scan a known fake secret first: a scanner that silently finds nothing must not PASS."""
    (ctx.workdir / "eaf_canary.py").write_text(CANARY, encoding="utf-8")
    res = ctx.run(self.id, [find_tool(self.tool), "scan", "--no-verify", "eaf_canary.py"],
                  cwd=ctx.workdir)
    out.evidence.append(res.evidence)
    try:
        ok = bool(json.loads(res.stdout).get("results"))
    except json.JSONDecodeError:
        ok = False
    if not ok:
        raise ScanNotExecuted("detect-secrets self-test failed: a planted canary secret was "
                              "not detected, so results cannot be trusted")
    out.notes.append("Scanner self-test passed (planted canary secret was detected).")


DetectSecretsAdapter._self_test = _self_test

SENSITIVE_NAME_GLOBS = [".env", ".env.*", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                        "*.p12", "*.pfx", "*.jks", "*.keystore", ".pypirc", ".htpasswd",
                        ".netrc", "credentials.json", "*.pem", "*.key", ".npmrc"]
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")


class SensitiveFilesAdapter(ScannerAdapter):
    id = "secrets.sensitive-files"
    title = "Credential / key files present in the source tree"
    category = "secrets"

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(files_examined=len(ctx.inventory.files))
        for f in ctx.inventory.files:
            name = f.rel.rsplit("/", 1)[-1]
            if not any(fnmatch.fnmatch(name, g) for g in SENSITIVE_NAME_GLOBS):
                continue
            if name.startswith(".env") and name.endswith(SAFE_ENV_SUFFIXES):
                continue
            if name.endswith((".pem", ".key")) or name == ".npmrc":
                try:
                    with open(ctx.root / f.rel, "r", encoding="utf-8", errors="replace") as fh:
                        head = fh.read(20000)
                except OSError:
                    head = ""
                marker = "_authToken" if name == ".npmrc" else "PRIVATE KEY-----"
                if marker not in head:
                    continue
            out.findings.append(Finding(
                check_id=self.id, rule_id="sensitive-file", severity=Severity.HIGH,
                message=f"File '{name}' typically holds credentials or private key material and "
                        "should not be stored in source control", file=f.rel))
        return out
