# Validation results – EAF Level 1

Sections 1–5 record version 0.1.0. Section 6 records what changed in 0.2.0 and the results
of the new checks. Numbers in sections 1–5 were not re-measured except where section 6 says so.

## 0.1.0

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
| EAF itself (37 files, samples excluded) | 3,094 Python + 1 JS | WARNING | WARNING | 0 / 0 / 0 / 8 (+28 suppressed) | 2.4 s / 2.4 s |
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
- detect-secrets flagged the fake AWS key literal inside a unit test (fixed in the test) and,
  later, the npm line quoted in this document (suppressed with reason).
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

## 6. Version 0.2.0 (2026-11-14)

Added scanner versions: semgrep 1.185.0, squawk 2.71.0, bun 1.4.4. Policy `eaf-baseline@1.1.0`,
guidance pack `eaf-practices@1.0.0`. 72 tests (71 passed, 1 skipped where PyYAML is absent).

### 6.1 Summary (median of 3 offline runs / 2 network runs)

| Target | Overall offline | Overall network | Findings c/h/m/l/i (network) | Time offline / network |
|---|---|---|---|---|
| `samples/api-mcp-vector-service` (new; 72 Python, 69 SQL, 41 TS lines) | FAIL | FAIL | 0 / 37 / 23 / 27 / 2 | 5.7 s / 7.0 s |
| `samples/vuln-python-service` | FAIL | FAIL | 0 / 22 / 13 / 19 / 0 | 5.3 s / 6.0 s |
| `samples/embedded-c-cpp` | FAIL | FAIL | 0 / 8 / 8 / 18 / 0 | 0.7 s / 0.8 s |
| `samples/web-ts-node` | FAIL | FAIL | 1 / 9 / 9 / 22 / 0 | 5.5 s / 6.3 s |
| `samples/clean-python-lib` (now with spec, architecture, changelog, …) | WARNING (pip-audit not executed) | PASS | 0 / 0 / 0 / 0 / 0 | 4.8 s / 5.7 s |
| EAF itself | WARNING | WARNING | 0 / 0 / 0 / 14 / 0 | 6.6 s / 6.8 s |
| A private React + Supabase web application (86 TS/JS files, 9.6k lines, 5 SQL migrations, 4 Python scripts) | FAIL | not run | 0 / 1 / 7 / 204 / 0 | 8.7 s |

Run time rose by about 4 s for Python/JS/TS targets: semgrep start-up, its self-test and
its version probe. All 12 sample configurations again produced one `results_digest` each and
left the source tree unmodified.

The increase in "low" findings on the old samples is the practice checks: the three defective
fixtures have no specification, architecture document, changelog, and so on.

### 6.2 New sample: api-mcp-vector-service

The fixture and the rules were written together, so detection here is by construction and
says nothing about recall on real code. What it does show is that each rule fires on its
target and stays silent on the adjacent correct example.

| Area | Planted | Reported |
|---|---|---|
| REST API code (Python) | CORS wildcard with credentials; JWT decoded without signature check; `verify=False` | semgrep ×3 (bandit also reports `verify=False`) |
| REST API contract | 3 operations without security; plain-http server; API key in query; no 429 | `security.openapi` OA002 ×3, OA003, OA005, OA006. The localhost server URL is not flagged |
| MCP server code | tool argument reaches a shell; tool opens an arbitrary path; HTTP transport on 0.0.0.0 | semgrep ×3. The harmless `add` tool is not flagged |
| MCP configuration | literal bearer token; plain-http remote server; unpinned `npx` package; shell launcher | `security.mcp-config` MCP001–MCP004. The pinned package and the `${env:…}` reference are not flagged; the token value is not in the report |
| PostgreSQL | write-all policy; `GRANT ALL … TO anon`; role password literal; `SECURITY DEFINER` without `search_path`; dynamic SQL by concatenation; RLS enabled without policy | PG003, PG005, PG006, PG004, PG007, PG002. The `format('%I')` function with pinned `search_path` is not flagged |
| pgvector | embeddings table without RLS and without ANN index; `SECURITY DEFINER` similarity search | VEC003, VEC001, VEC002 |
| Vector clients | plain-http Qdrant URL; FAISS index loaded with pickle enabled | semgrep ×2 |
| TypeScript client | `rejectUnauthorized: false`; SQL from template string; `jwt.decode`; `exec` with template; hardcoded password; unsanitised `dangerouslySetInnerHTML` | semgrep ×6. The parameterised query and the constant HTML are not flagged |
| Dependencies (network) | pinned 2024 versions | pip-audit: 26 advisories |

Fixture defect found by the tool: the first version of `001_init.sql` contained a stray `;`
that made it invalid SQL. squawk reported the syntax error; the built-in rules had silently
tolerated it. Invalid SQL is therefore only caught when squawk is installed.

### 6.3 Real application (private, not in this repository)

A React / TanStack Start / Supabase application, mostly generated with an AI app builder.
Compared with the 0.1.0 run on the same commit:

- **Fixed:** `bun.lock` is recognised (pinning PASS instead of a false "no lockfile");
  committed `__pycache__` files are reported; SQL is assessed instead of ignored.
- **`security.sql-postgres`:** 14 tables tracked, all with row level security enabled. Nine
  policies let the anonymous role read every row of content tables. Rated low because public
  read can be intentional; it needs a decision by the owner, which is the right outcome.
- **`security.semgrep`:** 2 findings. A hardcoded demo password in client code (true
  positive, previously only a generic "Secret Keyword" hit). `dangerouslySetInnerHTML` in a
  generated chart component that injects CSS built from a constant theme table (false
  positive in effect: no user input reaches it).
- **`quality.squawk`:** 73 low findings, 39 of them "missing IF NOT EXISTS". Noise for a
  database that is not yet live.
- **Practices:** 9 of 11 applicable practices not evidenced: no specification, no
  architecture document, no changelog, no contribution process, no security policy, README
  without usage and testing sections, no API contract, assistant instructions present but
  below the 80-word threshold (76 words).
  - Questionable: the API-contract practice fired because TanStack Start is classed as an API
    framework. Its server functions are not a REST API, so OpenAPI is the wrong ask here.
  - Questionable: the 80-word threshold is arbitrary; 76 words that say the right things
    should pass. Thresholds are configurable but the default has no empirical basis.
- **Still FAIL for a weak reason:** the overall FAIL is still caused by a committed `.env`
  that holds only public identifiers.
- **Dependencies:** `bun audit` works on this lockfile and reports advisories, including a
  critical one in the web framework, but only with `--allow-network`.

### 6.4 Not validated in 0.2.0

- No real project with an MCP server, an OpenAPI document, pgvector, or a dedicated vector
  database was assessed. Those checks have only seen the fixture.
- No project that actually practises spec-driven development was assessed, so false
  negatives of the practice checks (a project that has a spec in a place EAF does not look)
  are unmeasured.
- `docs.freshness` was exercised only on shallow or single-commit histories, where it
  reports that it cannot decide.
- YAML OpenAPI documents are covered by one unit test only.
