# Copilot instructions for the Engineering Assurance Framework (EAF) repository

## What this repository is
A Python 3.11+ CLI (`eaf`) that performs read-only, Level 1 static source assessments and
writes JSON/HTML reports. Core package: `src/eaf`. Scanner adapters: `src/eaf/scanners`.
Policies: `src/eaf/data/policies/*.toml`. Tests: `tests/` (pytest).

## Rules when changing code here
- The core must keep zero runtime dependencies (stdlib only). Scanners are external tools.
- Adapters return findings only. PASS/WARNING/FAIL is decided by the policy; NOT_APPLICABLE
  and NOT_EXECUTED are decided by the engine. Do not add status logic to adapters.
- Never add anything that builds, installs, imports or executes code from an assessed
  repository, or that loads executable configuration from it.
- Never add network access to a check unless it sets `requires_network = True`.
- Run every external tool through `ScanContext.run` (argv list, no shell).
- Never write secret values into findings or reports.
- Changing thresholds or controls in a policy requires a policy version bump; changing
  practices or advice text requires a guidance pack version bump.
- The specification is `specs/level1-source-assessment.md`. Read it first; change it first
  when requirements change; name the requirement ID in the test that covers it.
- Update `CHANGELOG.md` in the same change.
- Changing the JSON report structure requires a `REPORT_SCHEMA_VERSION` bump.
- Add or update tests for every behaviour change: `pytest`.

## Rules when using EAF results
- Run: `eaf assess <path> --depth 1` (add `--allow-network` only if the user agrees that
  dependency names and versions may be sent to public advisory services).
- Read `eaf-reports/eaf-report.json`; do not infer results from console output alone.
- Report NOT_EXECUTED and NOT_APPLICABLE checks explicitly. They provide no assurance.
- Never describe a PASS as a security certification, ISO 26262 compliance, or Audi IT
  approval. Use: "no findings above policy thresholds in the assessed scope".
- Do not add `[[suppressions]]` to make a result pass. Propose them to the user with a
  reason and let the user decide.
