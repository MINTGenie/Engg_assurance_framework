# Validation results – EAF 0.1.0, Level 1

Recorded 2026-11-13 on Linux x86_64, Python 3.13.18, Node 22.23.4.
Scanner versions: ruff 0.16.9, bandit 1.9.4, cppcheck 2.13.0, flawfinder 2.0.20,
ESLint 10.1.0 (+ @typescript-eslint/parser), detect-secrets 1.5.0, pip-audit 2.10.1, npm 10.9.9.
Policy: `eaf-baseline@1.0.0`, criticality `standard` unless stated.

Everything below is what the tool actually produced. Reports for the samples are in
`examples/reports/`. Reproduce with `eaf assess samples/<name> --allow-network`.

**Read this first**

- The four samples are small fixtures (41–149 lines) written for this prototype, with defects
  planted by the same author who wrote the adapters. Detection rates on them are optimistic
  and are not a measure of real-world recall.
- Two real code bases already present on the machine (pip 24.0 source, npm 10.9.9 `lib/`)
  were assessed as a realism and scale check. No automotive or Audi code was assessed.
- "False positive" is the author's judgement after reading the flagged line.

## 1. Summary

| Target | Lines | Overall (offline) | Overall (`--allow-network`) | Findings c/h/m/l (network) | Time offline / network (median of 3) |
|---|---|---|---|---|---|
| `samples/vuln-python-service` | 77 Python | FAIL | FAIL | 0 / 22 / 11 / 11 | 1.6 s / 2.1 s |
| `samples/embedded-c-cpp` | 149 C/C++ | FAIL | FAIL | 0 / 8 / 7 / 10 | 0.8 s / 0.9 s |
| `samples/web-ts-node` | 73 JS/TS | FAIL | FAIL | 1 / 9 / 7 / 14 | 1.7 s / 2.2 s |
| `samples/clean-python-lib` (negative control, `elevated`) | 41 Python | WARNING (pip-audit not executed) | PASS | 0 / 0 / 0 / 0 | 1.6 s / 2.1 s |
| EAF itself (37 files, samples excluded) | 3,094 Python + 1 JS | WARNING | WARNING | 0 / 0 / 0 / 8 (+27 suppressed) | 2.4 s / 2.4 s |
| pip 24.0 source (incl. vendored) | 184,623 Python | FAIL | not run | 0 / 68 / 396 / 958 | 18.7 s (single run) |
| npm 10.9.9 `lib/` | 14,045 JS | FAIL | not run | 0 / 0 / 4 / 48 | 2.3 s (single run) |

Times are wall clock for the whole CLI including interpreter start. About 0.6 s of every run
is detect-secrets start-up; tool version probes add roughly 0.5 s where the tool is Python or Node based. On pip, bandit took 11.0 s
and detect-secrets 7.3 s; everything else was under 0.5 s.

Other verified properties:

- **Reproducibility:** three consecutive runs per target and mode gave an identical
  `results_digest` in all 10 sample configurations.
- **Read-only:** `source_tree_unmodified` was `true` in every run, including pip and npm.
- **No execution of repository code:** `test_untrusted_repository_code_is_never_executed`
  plants `setup.py`, `conftest.py`, ESLint configs, npm lifecycle scripts, a Makefile, a
  CMake `execute_process`, a git hook and a git `fsmonitor` command; none ran. The same test
  confirms that an unhardened `git status` *does* run the planted command.
- **Unit tests:** 45 passed.

## 2. Planted defects: found and missed

### vuln-python-service (14 planted)

| Planted defect | Result |
|---|---|
| SQL injection via string formatting | found – bandit B608 (medium) |
| Command injection, `shell=True` | found – bandit B602 (high) |
| `eval` on request input | found – bandit B307 (medium) |
| `yaml.load` without safe loader | found – bandit B506 (medium) |
| `pickle.loads` on upload | found – bandit B301 (medium) |
| MD5 | found – bandit B324 (high) |
| Mutable default argument | found – ruff B006 (medium) |
| Bare `except: pass` | found – ruff E722, bandit B110 (low) |
| Undefined name | found – ruff F821 (high) |
| Fake AWS key, password, base64 token | found – detect-secrets ×3 (1 high, 2 medium) |
| Bind to `0.0.0.0` | found – bandit B104 (medium) |
| Unpinned dev requirements | found – `dependencies.pinning` ×2 (medium) |
| Outdated pinned flask / pyyaml / requests / jinja2 | found with network – pip-audit, 18 advisories; **NOT EXECUTED offline** |
| Flask `debug=True` passed through a config constant | **missed** – no data-flow analysis |

Not planted but correct: two unused imports (ruff F401).
Noise: bandit B403/B404 import notices (2, low).

### embedded-c-cpp (11 planted)

| Planted defect | Result |
|---|---|
| Off-by-one read `data[8]` | found – cppcheck arrayIndexOutOfBounds (high). Only found after adding the `-I` include heuristic; without it cppcheck could not see the array size |
| Memory leak on error path | found – cppcheck memleak (high) |
| `gets()` | found – flawfinder level 5 (high), cppcheck (medium) |
| Unbounded `strcpy` / `strcat` | found – flawfinder level 4 ×4 (high) |
| `fprintf(fp, text)` format string | found – flawfinder level 4 (high) |
| Unbounded `sprintf` | found only as flawfinder level 2 (low, below the warn threshold) |
| Uninitialised members | found – cppcheck uninitMemberVar ×2 (medium) |
| Raw owning pointer, no copy ctor / `operator=` | found – cppcheck ×2 (medium) |
| `fopen` result not checked for NULL | **missed** |
| `malloc` result not checked for NULL | **missed** |
| `delete` used for `new[]` (member pointer) | **missed** |

Not planted: cppcheck assertWithSideEffect ×2 in the test file (technically right, low value).
Noise: 7 of 9 flawfinder "low" hits (fixed-size `char` arrays, `strlen`, `atoi`, `fopen`).

### web-ts-node (16 planted)

| Planted defect | Result |
|---|---|
| `eval` on request input (JS) | found – no-eval (high) |
| `new Function` on input (TS) | found – no-new-func (high) |
| Duplicate key, unreachable code, `typeof` typo, NaN comparison | found – 4 rules (medium) |
| `debugger`, duplicate `case`, empty `catch` (TS) | found (medium / medium / low) |
| Loose equality | found – eqeqeq (low) |
| Unused variables, `var` | found (low) |
| Committed `.env` | found – `secrets.sensitive-files` (high) |
| Credentials in a URL inside `.env` | found – detect-secrets Basic Auth (high) |
| Outdated express / lodash / minimist | found with network – npm audit, 9 packages (1 critical, 5 high, 3 low); **NOT EXECUTED offline** |
| Hex session secret in `.env` | **missed** by detect-secrets |
| Implied eval `setTimeout("…")` | **missed** – the rule needs known globals, which EAF does not assume |
| Assignment inside a condition | **missed** – the fixture uses the double-parenthesis form that the rule exempts |

Debatable: eqeqeq on `== null` in TypeScript is a common deliberate idiom.

### clean-python-lib (negative control)

No findings. While building it, pip-audit reported a real advisory for the originally pinned
`pytest==8.3.4`; the fixture was moved to 9.0.3. Offline the overall result is WARNING, not
PASS, because the vulnerability lookup could not run. That is intended behaviour.

## 3. False positives and noise on real code

### EAF's own repository
- bandit B105 "hardcoded password" on `PASS = "PASS"` and similar – 3 false positives.
- bandit B404/B405/B603/B607 on every subprocess and XML use – 22 notices; correct but uninformative for a
  tool whose job is to run scanners. Suppressed with reasons in `eaf-profile.toml`.
- bandit B314 on parsing cppcheck's XML – accepted for the prototype, suppressed with reason.
- `hygiene.tests-present` reported "no JavaScript tests" because of one bundled ESLint config
  file – false positive, suppressed.
- detect-secrets flagged the fake AWS key literal inside a unit test – fixed in the test.
- Remaining real warnings: 6 complexity (ruff C901), no LICENSE file, no CI configuration.

### pip 24.0
- 1,263 of 1,341 ruff findings (94 %) are in `_vendor/`. Without an `exclude` in the profile,
  third-party code dominates the result.
- All 55 "high" ruff F821 findings are Python 2 names (`unicode`, `basestring`) in
  compatibility shims – false positives.
- detect-secrets: 1 hit, a URL example in a docstring – false positive.
- bandit B602 `shell=True` in `commands/configuration.py:239` – true positive.

### npm 10.9.9 `lib/`
- First run: a **false FAIL**. EAF parsed CommonJS files as ES modules, so
  `protected` was rejected as a reserved word (rated high). Fixed: each `.js` file is now
  classified by content. Regression test added.
- First run: inline `eslint-disable` comments naming plugin rules produced "rule not found"
  errors. Fixed: counted in a note, not reported as findings.
- detect-secrets "Secret Keyword" on `const passwordPrompt = 'npm password: '` – false
  positive that still makes the secrets check, and so the overall result, FAIL.
- no-unsafe-finally ×2 in `commands/doctor.js` – plausible true positives, not investigated.

## 4. Defects found in EAF itself during validation

| Defect | Effect | Status |
|---|---|---|
| detect-secrets silently scans nothing when given paths outside its working directory | secrets check reported PASS on a file full of secrets | fixed; a canary self-test now turns a blind scanner into NOT_EXECUTED |
| cppcheck analysed headers as standalone units | false "unused member" findings | fixed |
| cppcheck had no include paths | missed the out-of-bounds read | mitigated with an `-I` heuristic |
| pip-audit returns aliases in varying order and duplicate advisories | `results_digest` differed between identical runs | fixed (normalised, de-duplicated) |
| ESLint source type for `.js` | false FAIL on CommonJS | fixed |

The first row is the important one: a scanner that fails silently looks exactly like clean
code. Only detect-secrets has a self-test today.

## 5. Unsupported or not executed

- No security-specific analysis for JavaScript/TypeScript: `EAF-SEC-01` is NOT APPLICABLE for
  a pure JS/TS repository. Only ESLint core rules run.
- No TypeScript type checking and no type-aware lint rules.
- Dependency vulnerability lookups: NOT EXECUTED without `--allow-network`; not supported for
  `pyproject.toml`, `setup.py`, Poetry, uv, Pipenv, yarn, pnpm, Conan, vcpkg, CMake
  FetchContent or git submodules.
- Languages detected but not assessed: everything except Python, C, C++, JavaScript, TypeScript
  (the shell script in npm `lib/` was reported as not assessed).
- Git history is not scanned for secrets.
- Not tested: Windows, macOS, repositories above ~185k lines, monorepos with several
  package roots, a live GitHub Copilot session using the skill.
