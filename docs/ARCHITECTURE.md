# Architecture (as built)

```
eaf assess <path>
   │
   ├─ profile.py     load engineering context profile (TOML)
   ├─ policy.py      load versioned policy → PolicyAdapter
   ├─ discovery.py   walk tree (no symlinks) → Inventory: languages, manifests,
   │                 frameworks, build systems, CI; source digest
   ├─ gitinfo.py     revision from .git files; dirty state via hardened git
   ├─ engine.py      for each ScannerAdapter:
   │                    applicable? → NOT_APPLICABLE
   │                    deselected / depth / network / tool missing → NOT_EXECUTED
   │                    scan() → findings → suppressions → policy.evaluate() → PASS/WARNING/FAIL
   │                 then: controls, overall status, results digest, limitations
   └─ report/        JSON (canonical) and HTML (rendered from the same dict)
```

Design rules:

- **Adapters report findings; the policy decides status.** An adapter never returns
  PASS/FAIL. This keeps thresholds in one versioned place.
- **The engine owns NOT_APPLICABLE and NOT_EXECUTED.** An adapter crash, a missing tool or a
  timeout becomes NOT_EXECUTED with a reason and never aborts the run.
- **All tool execution goes through `runner.run_tool`**: argv lists, no shell, timeout,
  proxy variables stripped unless the adapter declares `requires_network` and the user
  passed `--allow-network`, output hashed and stored as evidence.
- **The JSON report is the contract** (`schema_version`). HTML is a view of it.

## Adding a scanner adapter

```python
# my_pkg/semgrep_adapter.py
from eaf.models import Finding, Severity
from eaf.runner import find_tool
from eaf.scanners.base import ScannerAdapter, ScanContext, ScanNotExecuted, ScanOutput

class SemgrepAdapter(ScannerAdapter):
    id = "security.semgrep"
    title = "Semgrep rules"
    category = "security"
    tool = "semgrep"                      # executable; presence + version handled by the base
    languages = ("python", "javascript")  # empty tuple = language independent
    requires_network = False

    def scan(self, ctx: ScanContext) -> ScanOutput:
        out = ScanOutput(files_examined=len(self.target_files(ctx)))
        res = ctx.run(self.id, [find_tool(self.tool), "--json", "--config", "/path/to/rules",
                                *[ctx.abs(f) for f in self.target_files(ctx)]])
        out.evidence.append(res.evidence)
        if res.exit_code not in (0, 1):
            raise ScanNotExecuted(f"semgrep failed: {res.stderr[:200]}")
        ...  # parse res.stdout → out.findings.append(Finding(check_id=self.id, ...))
        return out
```

Register it either in `eaf.scanners.BUILTIN_ADAPTERS` or, from a separate package:

```toml
[project.entry-points."eaf.scanners"]
semgrep = "my_pkg.semgrep_adapter:SemgrepAdapter"
```

Adapter checklist: disable the tool's cache/fix/auto-config features; never let it load
configuration *code* from the assessed repository; map tool severities to
`info|low|medium|high|critical`; verify that paths outside the tool's working directory are
actually scanned (detect-secrets silently ignores them – see the canary self-test in
`scanners/secrets.py`).

## Adding an organizational policy (e.g. SWEAP)

1. Thresholds and control mapping only → write a TOML file modelled on
   `data/policies/eaf-baseline.toml` and pass `--policy path/to/policy.toml`.
2. Custom logic → implement a class with the same methods as `ThresholdPolicyAdapter`
   (`describe`, `thresholds`, `evaluate`, `overall`, `controls`), register it under the
   `eaf.policy_adapters` entry-point group and reference it with `adapter = "<name>"` in the
   policy's `[policy]` table.

Controls with no mapped check are reported as NOT_EXECUTED ("needs manual evidence or a
deeper level"), so a policy can list requirements that Level 1 cannot answer without
pretending they are covered.

## Reserved extension points

| Future need | Hook that exists today |
|---|---|
| Depth 2–4 (build, runtime, system) | `--depth`, `DEPTHS`, `ScannerAdapter.min_depth`; depths > 1 are rejected with exit 2 |
| Function and multi-repository scope | `--scope` values are reserved and rejected; module/component/repository work on any directory |
| More languages | `LANGUAGE_BY_EXT` already detects them and reports them as not assessed |
| More scanners / policies | entry-point groups `eaf.scanners`, `eaf.policy_adapters` |
