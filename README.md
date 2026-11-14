# Engineering Assurance Framework (EAF) – Level 1 prototype

EAF is a standalone, read-only engineering quality assessment toolkit for AI-assisted and
conventional software development. Phase 1 implements **Level 1: static source inspection**.

```
eaf assess <path> --depth 1
```

It inventories a repository, runs established open-source analysers through adapters, checks
for evidence of engineering practices (specification, documentation, review process), applies
a versioned policy, and writes JSON, HTML and Markdown reports. Every finding carries fix
guidance and, where one exists, a reference to a public standard category (CWE, OWASP).

EAF has two jobs:

1. **Guide the developer.** Tell them what is missing and how to add it, so that a project
   built with AI assistance is engineered rather than merely generated.
2. **Give reviewers evidence.** Record exactly which checks ran, with which tool versions,
   on which revision, what they found, and what was *not* checked.

> **What a result means.** EAF output is an automated engineering quality *indication*.
> A PASS is **not** a security certification, does **not** establish ISO 26262 / ISO 21434 /
> ASPICE compliance, and is **not** an Audi IT or release approval. It means only that the
> listed tools found nothing above the policy thresholds in the assessed scope.

## What it checks

| Category | Check id | Tool | Applies to |
|---|---|---|---|
| Code quality | `quality.ruff` | ruff | Python |
| | `quality.cppcheck` | cppcheck | C, C++ |
| | `quality.eslint-js`, `quality.eslint-ts` | ESLint (core rules, EAF-owned config) | JavaScript, TypeScript |
| | `quality.squawk` | squawk | PostgreSQL migrations |
| Security | `security.bandit` | bandit | Python |
| | `security.flawfinder` | flawfinder | C, C++ |
| | `security.semgrep` | semgrep with 17 bundled EAF rules | Python, JS, TS: REST API code, MCP servers, vector-store clients, web |
| | `security.sql-postgres` | built-in | PostgreSQL: row level security, policies, grants, `SECURITY DEFINER`, dynamic SQL; pgvector tables and search functions |
| | `security.openapi` | built-in | OpenAPI 2/3 documents: authentication per operation, transport |
| | `security.mcp-config` | built-in | MCP configuration files: credentials, transport, unpinned packages |
| Secrets | `secrets.detect-secrets` | detect-secrets | any text file |
| | `secrets.sensitive-files` | built-in | any |
| Dependencies | `dependencies.pinning` | built-in (offline) | pip, npm, Bun |
| | `dependencies.pip-audit`, `.npm-audit`, `.bun-audit` | pip-audit, npm, bun (**network, opt-in**) | pip, npm, Bun lockfiles |
| Hygiene | `hygiene.readme`, `.license`, `.gitignore`, `.tests-present`, `.ci-config`, `.large-files`, `.tracked-artifacts` | built-in | any |
| Practices | `practice.*` (12 in the default pack) | built-in, driven by the guidance pack | see below |

Detection also covers frameworks (Flask, Django, FastAPI, React, Express, …), dependency
manifests and lockfiles, and build systems (CMake, Make, Bazel, Meson, setuptools, npm scripts,
tsc, …), API frameworks, OpenAPI documents, data stores (PostgreSQL, Supabase, pgvector, Qdrant,
Pinecone, Weaviate, Chroma, Milvus, FAISS, …) and MCP usage. Other languages (Java, Go, Rust,
…) are detected and reported as **not assessed**.

## Engineering practices and guidance

The `practice.*` checks look for evidence that the project is engineered deliberately:

| Practice | What counts as evidence |
|---|---|
| `spec.present`, `spec.acceptance-criteria` | a written specification (`specs/`, `docs/spec*`, `*.feature`, …) with testable criteria or requirement IDs |
| `docs.readme-sections` | README covers purpose, setup, usage, testing |
| `docs.architecture` | architecture description or ADRs |
| `docs.changelog`, `docs.contribution-process`, `docs.security-policy` | changelog; CONTRIBUTING / PR template / CODEOWNERS; SECURITY.md or threat model |
| `docs.freshness` | documentation last changed within 90 days of the last code change (needs full git history) |
| `docs.api-contract` | an OpenAPI document, when an API framework is detected |
| `docs.data-model` | versioned migrations, when a database is detected |
| `docs.mcp-tools` | MCP server and tools are described, when MCP is detected |
| `ai.agent-instructions` | AGENTS.md / copilot-instructions / CLAUDE.md, unless the profile says `conventional` |

A missing practice produces a WARNING with *why it matters* and *what to do*; it does not fail
the assessment unless the profile sets `criticality = "elevated"`. These checks establish that
an artefact exists and has minimal substance. They cannot judge whether a specification is
correct or whether the code follows it.

**All guidance is configurable.** Practices, their severity, the paths that count as
evidence, the advice text, and the fix guidance attached to scanner findings live in a
versioned guidance pack (`src/eaf/data/guidance/eaf-practices.toml`). A team pack extends it:

```toml
[guidance]
id = "team-x-practices"
version = "1.0.0"
extends = "eaf-practices"
disable = ["docs.changelog"]          # globs allowed

[[practice]]                          # same id replaces, new id adds
id = "spec.present"
title = "Requirements are exported from DOORS"
severity = "high"
paths = ["doors/*.csv"]
why = "Team rule."
how = "Export the module to doors/ before each merge."

[[remediation]]                       # advice for scanner findings; your entries win
check = "security.bandit"
rule = "B602"
guidance = "Use the internal process wrapper instead of subprocess."
```

```bash
eaf guidance                          # print every practice with its why/how
eaf assess . --guidance team-x.toml   # or [assessment] guidance = "team-x.toml" in the profile
```

The pack id, version and hash are recorded in every report.

## Standards coverage

Each report contains a table for **OWASP Top 10 (2021)** and **OWASP API Security Top 10
(2023)** showing, per category, which checks contribute evidence, their status, the number of
findings in that category, and what is *not* looked at. Coverage is only ever `partial` or
`none`: static inspection can find instances of a weakness class, never prove its absence.
Access-control logic, design, logging and business-flow categories are largely outside what
Level 1 can evaluate, and the report says so.

## Installation

Requires Python ≥ 3.11. The EAF core has no Python dependencies; scanners are separate tools.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[scanners,dev]"     # eaf + ruff, bandit, flawfinder, detect-secrets, pip-audit,
                                     # semgrep, squawk, pyyaml, pytest

# not installable through pip:
sudo apt-get install cppcheck                         # C/C++
npm install -g eslint @typescript-eslint/parser       # JS / TS (Node.js required)
# optional: bun (https://bun.sh) for auditing bun.lock

eaf scanners        # shows every adapter, tool version, or MISSING
```

## Testing

```bash
pytest              # 72 tests; scanner integration tests skip if a tool is missing
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
eaf assess path/to/repo --guidance team-pack.toml     # your own practices and advice
eaf scanners | eaf policies | eaf guidance
```

Exit codes: `0` overall status below the `--fail-on` level, `1` at or above it (default: FAIL),
`2` usage error or unimplemented depth/scope.

Output directory:

```
eaf-reports/
  eaf-report.json      machine-readable, schema_version 1.1
  eaf-evidence.md      short evidence summary to attach to a review or ticket
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
- Policy and guidance pack id, version and SHA-256; the full context profile; all suppressions
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
src/eaf/data/       bundled policies, guidance pack, standards mapping, semgrep rules, ESLint config
tests/              unit + integration tests
samples/            five fixture repositories (four deliberately defective)
specs/              EAF's own specification with requirement IDs
examples/reports/   JSON + HTML reports generated from the samples and from EAF itself
docs/               architecture, validation results, limitations and roadmap
.github/            Copilot instructions, skill and prompt
```

## Further reading

- `docs/VALIDATION.md` – actual results on the samples: findings, misses, false positives, timing
- `docs/LIMITATIONS_AND_ROADMAP.md` – known limitations and the Phase 2 proposal
- `docs/ARCHITECTURE.md` – design and how to add a scanner or policy adapter
- `docs/COPILOT.md` – using EAF from GitHub Copilot
