# Engineering Assurance Framework (EAF) – Level 1 prototype

EAF is a standalone, read-only engineering quality assessment toolkit for AI-assisted and
conventional software development. Phase 1 implements **Level 1: static source inspection**.

```
eaf assess <path> --depth 1
```

It inventories a repository, runs established open-source analysers through adapters, applies
a versioned policy, and writes a JSON and an HTML assurance report.

> **What a result means.** EAF output is an automated engineering quality *indication*.
> A PASS is **not** a security certification, does **not** establish ISO 26262 / ISO 21434 /
> ASPICE compliance, and is **not** an Audi IT or release approval. It means only that the
> listed tools found nothing above the policy thresholds in the assessed scope.

## What it checks

| Category | Check id | Tool | Languages |
|---|---|---|---|
| Code quality | `quality.ruff` | ruff | Python |
| | `quality.cppcheck` | cppcheck | C, C++ |
| | `quality.eslint-js`, `quality.eslint-ts` | ESLint (core rules, EAF-owned config) | JavaScript, TypeScript |
| Security | `security.bandit` | bandit | Python |
| | `security.flawfinder` | flawfinder | C, C++ |
| Secrets | `secrets.detect-secrets` | detect-secrets | any text file |
| | `secrets.sensitive-files` | built-in | any |
| Dependencies | `dependencies.pinning` | built-in (offline) | pip, npm |
| | `dependencies.pip-audit` | pip-audit (**network, opt-in**) | pip |
| | `dependencies.npm-audit` | npm audit (**network, opt-in**) | npm |
| Hygiene | `hygiene.readme`, `.license`, `.gitignore`, `.tests-present`, `.ci-config`, `.large-files` | built-in | any |

Detection also covers frameworks (Flask, Django, FastAPI, React, Express, …), dependency
manifests and lockfiles, and build systems (CMake, Make, Bazel, Meson, setuptools, npm scripts,
tsc, …). Other languages (Java, Go, Rust, …) are detected and reported as **not assessed**.

## Installation

Requires Python ≥ 3.11. The EAF core has no Python dependencies; scanners are separate tools.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[scanners,dev]"     # eaf + ruff, bandit, flawfinder, detect-secrets, pip-audit, pytest

# not installable through pip:
sudo apt-get install cppcheck                         # C/C++
npm install -g eslint @typescript-eslint/parser       # JS / TS (Node.js required)

eaf scanners        # shows every adapter, tool version, or MISSING
pytest              # 44 tests; scanner integration tests skip if a tool is missing
```

A missing scanner never aborts an assessment: its check is reported as `NOT_EXECUTED` with
the reason, and the overall result cannot be a clean PASS.

## Usage

```bash
eaf assess path/to/repo --depth 1                    # offline, reports in ./eaf-reports
eaf assess path/to/repo --allow-network              # + known-vulnerability lookups
eaf assess path/to/repo --profile my-profile.toml -o out/
eaf assess path/to/repo --only 'security.*' --only 'secrets.*'
eaf assess path/to/repo/src/module --scope module
eaf assess path/to/repo --policy sweap-placeholder   # or a path to a policy .toml
eaf assess path/to/repo --fail-on warning            # stricter exit code for CI
eaf init-profile                                     # writes eaf-profile.toml template
eaf scanners | eaf policies
```

Exit codes: `0` overall status below the `--fail-on` level, `1` at or above it (default: FAIL),
`2` usage error or unimplemented depth/scope.

Output directory:

```
eaf-reports/
  eaf-report.json      machine-readable, schema_version 1.0
  eaf-report.html      self-contained, no scripts, no external resources
  evidence/            raw stdout/stderr of every scanner run (omit with --no-evidence)
```

`evidence/` contains raw scanner output, which can include source snippets. Treat it with the
same confidentiality as the repository.

### Statuses

| Status | Meaning |
|---|---|
| `PASS` | The check ran; no un-suppressed finding reached the policy's warn threshold. |
| `WARNING` | The check ran; findings at or above `warn_at` but below `fail_at`. |
| `FAIL` | The check ran; at least one finding at or above `fail_at`. |
| `NOT_APPLICABLE` | Nothing in scope for this check (e.g. no C/C++ files). |
| `NOT_EXECUTED` | The check applies but did not run: tool missing, network not allowed, tool error/timeout, deselected, or needs a deeper level. Always carries a reason. |

Overall: FAIL if any check failed; WARNING if any warned **or any applicable check was not
executed**; PASS only if everything applicable ran and passed.

### What every report records

- Git revision, branch and dirty state; `source_digest` (SHA-256 over all in-scope files) and
  whether the tree was unmodified during the assessment
- EAF version, each scanner's version, exact commands, exit codes, output hashes
- Policy id, version and SHA-256; the full engineering context profile; all suppressions
- Inventory, excluded paths, languages that were detected but not assessed
- `results_digest`: hash of statuses + findings, for comparing two runs

Same source + same tool versions + same policy ⇒ same `results_digest`. Network-based checks
additionally depend on the advisory database at the time of the run.

## Engineering context profile

`eaf-profile.toml` in the assessed directory (or `--profile`) describes the project and tunes
strictness. See `eaf init-profile` for the annotated template.

```toml
[project]
name = "can-gateway"
owner = "team-x"

[context]
criticality = "elevated"          # prototype | standard | elevated (strictness, not an ASIL)
development_mode = "ai-assisted"  # ai-assisted | conventional | mixed | unknown
ai_tools = ["GitHub Copilot"]

[assessment]
policy = "eaf-baseline"
exclude = ["third_party/*"]

[[suppressions]]                  # a reason is mandatory; suppressed findings stay visible
check = "security.bandit"
rule = "B404"
reason = "subprocess use reviewed in PR 123"
```

## Policies and organizational adapters

Policies are versioned TOML files (`src/eaf/data/policies/`). A policy sets `fail_at` /
`warn_at` severities per check, per-criticality overrides, and maps checks to controls.

- `eaf-baseline@1.0.0` – default thresholds.
- `sweap-placeholder@0.0.1` – demonstrates the mapping mechanism for a SWEAP adapter.
  **It contains no real SWEAP requirements**; control IDs are invented placeholders.

A policy that needs logic beyond thresholds can be a Python class registered under the
`eaf.policy_adapters` entry-point group. See `docs/ARCHITECTURE.md`.

## Safety properties of the tool itself

| Requirement | How it is met |
|---|---|
| Read-only | Scanners get no fix/cache flags; reports go outside the tree; the source digest is compared before/after. |
| No execution of repository code | No build, install, import or test run. Repository ESLint configs are not loaded; `npm audit` runs on a copy with `--ignore-scripts`; pip-audit runs with `--no-deps --disable-pip`; git runs with hooks and fsmonitor disabled. Covered by `test_untrusted_repository_code_is_never_executed`. |
| No transmission of repository content | Default is fully offline and proxy variables are stripped from scanner environments. `--allow-network` sends only dependency names and versions to PyPI / npm advisory services. detect-secrets runs with `--no-verify`. |
| No LLM dependency | None. |
| Secrets not copied into reports | Reports contain secret type, file and line only. |

This is process-level hardening, not a sandbox. For hostile repositories run EAF inside a
container without network access.

## Repository layout

```
src/eaf/            CLI, engine, discovery, policy, profile, report writers
src/eaf/scanners/   one adapter per tool
src/eaf/data/       bundled policies and the EAF ESLint config
tests/              unit + integration tests
samples/            four fixture repositories (three deliberately defective)
examples/reports/   JSON + HTML reports generated from the samples and from EAF itself
docs/               architecture, validation results, limitations and roadmap
.github/            Copilot instructions, skill and prompt
```

## Further reading

- `docs/VALIDATION.md` – actual results on the samples: findings, misses, false positives, timing
- `docs/LIMITATIONS_AND_ROADMAP.md` – known limitations and the Phase 2 proposal
- `docs/ARCHITECTURE.md` – design and how to add a scanner or policy adapter
- `docs/COPILOT.md` – using EAF from GitHub Copilot
