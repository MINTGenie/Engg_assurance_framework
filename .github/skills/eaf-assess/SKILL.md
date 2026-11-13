---
name: eaf-assess
description: Run an Engineering Assurance Framework (EAF) Level 1 source assessment on a repository or directory and summarise the JSON report. Use when asked to assess, check or review the engineering quality, security hygiene, secrets or dependency risk of code, including AI-generated code, before review or merge.
---

# EAF Level 1 source assessment

EAF is a read-only static assessment CLI. It does not build or run the code under assessment.

## Procedure

1. Check the tool: `eaf scanners`. If `eaf` is missing, tell the user to install it
   (`pip install -e ".[scanners]"` in the EAF repository). Do not substitute your own review
   for a scanner that shows `MISSING`; say that the check will be NOT EXECUTED.
2. Choose the scope: the repository root by default, or the directory the user named
   (`--scope module` or `--scope component` for a sub-directory).
3. Run offline first:
   `eaf assess <path> --depth 1 --output eaf-reports`
   Exit code 1 means the overall status is FAIL; that is a result, not a tool error.
   Exit code 2 is a usage error.
4. Only if the user explicitly agrees that dependency names and versions may be sent to
   PyPI / npm advisory services, re-run with `--allow-network`.
5. Read `eaf-reports/eaf-report.json` and summarise from it:
   - `summary.overall_status` and `summary.overall_reason`
   - scope: `assessment.scope.git.revision`, `dirty`, `source_digest`, policy id and version
   - every check with status FAIL or WARNING: top findings with `file:line`, `rule_id`, severity
   - every check with status NOT_EXECUTED, with its `reason`
   - `inventory.unsupported_languages` and the `limitations` list
6. Point the user to `eaf-reports/eaf-report.html` for the full report.

## Fixing findings

- Fix real defects in the code. Re-run the assessment and compare.
- If a finding is a false positive, explain why and propose a `[[suppressions]]` entry for
  `eaf-profile.toml` with a concrete `reason`. Add it only after the user confirms.
- Never weaken a policy, exclude paths, or skip checks to change the result unless the user
  asks for exactly that.

## Wording rules (mandatory)

- Never state or imply that a PASS is a security certification, a safety argument,
  ISO 26262 / ISO 21434 / ASPICE compliance, or Audi IT / release approval.
- Say "no findings above the policy thresholds in the assessed scope", not "secure" or
  "compliant".
- NOT EXECUTED and NOT APPLICABLE mean no evidence. Report them as gaps.
- Level 1 inspects source text only. Do not claim anything about build, runtime behaviour,
  test results or coverage.
- If the work tree is dirty (`assessment.scope.git.dirty`), say that the result does not
  correspond to a commit.
