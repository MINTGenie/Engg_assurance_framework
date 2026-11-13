# Known limitations and recommended Phase 2 roadmap

## What a Level 1 result can and cannot support

It can show that a defined set of static tools, at recorded versions, under a recorded
policy, reported nothing above thresholds for an identified source state.

It cannot show functional correctness, absence of vulnerabilities, safety, or conformance to
ISO 26262, ISO/SAE 21434, ASPICE, MISRA, AUTOSAR guidelines, or any Audi process. EAF is not
a qualified tool in the sense of ISO 26262-8 clause 11, and nothing in it has been reviewed
by Audi IT security, the SWEAP process owner, or a safety organisation.

## Known limitations of 0.1.0

**Analysis depth**
- Lexical and intra-file analysis only. No taint or data-flow analysis across files.
- C/C++: no compilation database, so include paths and defines are guessed. cppcheck skips
  code behind unknown `#ifdef` configurations. No MISRA C/C++ or CERT rule sets.
- JS/TS: ESLint core rules only; no security rules, no type checking, `no-undef` disabled.
- Tests: presence by file name only. No execution, no coverage.
- Secrets: working tree only, no git history; entropy heuristics produce false positives
  and miss some values (see `VALIDATION.md`).
- Dependencies: vulnerability lookups need network access and only cover fully pinned
  `requirements*.txt` and `package-lock.json`. pip-audit provides no severity, so every
  advisory is rated high. No license or SBOM analysis.

**Trust in results**
- Only detect-secrets has a self-test. Any other scanner that silently skips files would
  still be reported as PASS.
- Inline suppressions in source (`# noqa`, `# nosec`, `eslint-disable`,
  `// cppcheck-suppress`) are honoured by ruff, bandit and ESLint and are not counted or
  listed in the report.
- `eaf-profile.toml` is read from the assessed repository. Whoever controls the repository
  controls excludes, criticality and suppressions. All of it is recorded in the report, but
  nothing prevents it.
- Severity mappings from tool-native scales to EAF's five levels are the author's choice
  and have not been reviewed.
- Reproducibility depends on identical scanner versions; EAF records them but does not pin
  or enforce them. Network results change as advisory databases change.

**Isolation**
- Hardening is at process level (no shell, no repo config code, no hooks, proxies stripped).
  It is not a sandbox: a scanner with a parser vulnerability could be exploited by a hostile
  file, and nothing technically blocks a scanner from opening a socket.
- `git status` is executed (hardened) to determine the dirty state.

**Scope and platform**
- Depth 2–4 and the `function` and `multi-repository` scopes are reserved and rejected.
- One profile per assessment; no per-package configuration in monorepos.
- Tested on Linux only. Largest tree assessed: 185k lines of Python in 19 s.
- The SWEAP policy is a placeholder with invented control IDs.
- The Copilot skill and prompt files were not exercised against a live Copilot agent.

## Recommended Phase 2 roadmap

Ordered by how much each item improves the trustworthiness of a result.

**1. Make results trustworthy before making them broader**
- Canary self-test for every scanner adapter (plant a known defect, require detection).
- Report and count inline suppressions; option to ignore them.
- Pin scanner versions per policy version and report NOT_EXECUTED on mismatch; ship a
  container image with the pinned tool set and run it with `--network=none`.
- Baseline / diff mode: assess only what a change introduced, compared with a stored
  baseline or a base revision. This is what makes the tool usable on legacy code and for
  reviewing AI-generated changes.
- Pilot on three to five real SDV repositories and measure false-positive rates with the
  owning teams before tuning thresholds.

**2. Close the analysis gaps found in validation**
- Semgrep adapter with a pinned, locally stored rule set (JS/TS security, cross-language taint).
- `compile_commands.json` support for cppcheck and a clang-tidy adapter; MISRA/CERT rule
  sets where licences allow.
- OSV-Scanner or an offline advisory database mirror so dependency checks run without
  internet access; support for Poetry, uv, yarn, pnpm, Conan, vcpkg.
- gitleaks adapter including git history; SBOM (CycloneDX) and licence inventory.
- SARIF import/export so existing CI scanner output can be reused and results appear in
  code-scanning UIs.

**3. Organisational policy adapters**
- Replace `sweap-placeholder` with the real control catalogue, written with the SWEAP
  process owner. Decide which controls Level 1 can evidence and which stay NOT_EXECUTED.
- Policy signing and a central policy repository so teams cannot weaken thresholds locally.
- Profile governance: who may set criticality and approve suppressions; expiry dates on
  suppressions.

**4. Deeper levels and wider scopes**
- Level 2 (build): compile in an isolated container; compiler warnings, type checking
  (tsc, mypy), build reproducibility.
- Level 3 (runtime): run tests, coverage, sanitizers, fuzzing smoke tests.
- Level 4 (system): integration-level evidence; needs definition with the target teams.
- Function-level scope (changed functions from a diff) and multi-repository roll-up reports.

**5. Integration**
- CI templates (GitHub Actions, GitLab, Jenkins) and a pre-merge gate using `--fail-on`.
- JSON Schema for the report and a compatibility policy for `schema_version`.
- Trend storage across runs.

## Open decisions for the project owner

- Licence and distribution model for EAF (no LICENSE file is included).
- Whether dependency lookups against public advisory services are acceptable, or an
  internal mirror is mandatory.
- Whether an unexecuted applicable check should cap the overall result at WARNING
  (current policy) or FAIL.
- Who owns thresholds and severity mappings.
