# Specification: EAF Level 1 source assessment

Status: implemented in 0.2.0 unless marked otherwise. Source: project owner's requests of
2026-11-13 and 2026-11-14. Change this document first when requirements change.

## Purpose

An independent, reusable engineering quality assessment toolkit for AI-assisted and
conventional software development. It guides developers towards standard engineering
practice and gives reviewers evidence of which checks were performed.

## Out of scope

- Any statement of security certification, ISO 26262 / ISO 21434 / ASPICE compliance, or
  Audi IT approval.
- Building, executing or testing the assessed software (Levels 2–4).
- Judging the content of specifications or documentation.

## Requirements and acceptance criteria

| ID | Requirement | Acceptance criterion | Verified by |
|---|---|---|---|
| REQ-001 | Standalone CLI `eaf assess <path> --depth 1` accepts a local repository or directory | Exit code 0/1 with reports written; exit 2 for unimplemented depth or scope | `tests/test_cli_report.py` |
| REQ-002 | Detect languages, frameworks, dependency manifests, build systems | Inventory lists them for a mixed fixture tree | `tests/test_discovery.py` |
| REQ-003 | Read-only inspection with established open-source tools | Source digest identical before and after; `source_tree_unmodified` true | `tests/test_engine.py`, `tests/test_scanners.py` |
| REQ-004 | Check code quality, security, secrets, dependency risk, hygiene | Each category has at least one adapter producing findings on the samples | `tests/test_scanners.py` |
| REQ-005 | Support Python, C/C++, JavaScript/TypeScript with extensible adapters | A tool-backed adapter exists per language; entry-point group `eaf.scanners` | `tests/test_scanners.py` |
| REQ-006 | Standardised JSON and HTML reports | Reports written; HTML has no scripts or external resources | `tests/test_cli_report.py` |
| REQ-007 | Distinguish PASS, FAIL, WARNING, NOT APPLICABLE, NOT EXECUTED | All five statuses produced by distinct conditions; NOT_* always carry a reason | `tests/test_engine.py` |
| REQ-008 | Record scanner versions, git revision, scope, evidence | Present in the JSON report | `tests/test_cli_report.py`, `tests/test_scanners.py` |
| REQ-009 | Configurable engineering context profile | Profile changes strictness, excludes, suppressions | `tests/test_policy_profile.py` |
| REQ-010 | Organisational policy adapters, including SWEAP | Policy TOML + entry-point group; SWEAP shipped only as a placeholder | `tests/test_policy_profile.py` (mechanism). **Real SWEAP content: open** |
| REQ-011 | No mandatory LLM dependency | Core has no runtime dependencies | `pyproject.toml` |
| REQ-012 | No external transmission of repository content | Offline by default; network checks are opt-in and send package names/versions only | `tests/test_scanners.py`, `tests/test_data_api_mcp.py` |
| REQ-013 | No automatic execution of untrusted build scripts | Planted setup.py, lint configs, npm scripts, Makefile, git hooks do not run | `tests/test_scanners.py::test_untrusted_repository_code_is_never_executed` |
| REQ-014 | Versioned policies, reproducible results | Policy id/version/hash recorded; identical `results_digest` for identical input | `tests/test_engine.py` |
| REQ-015 | Reserve deeper levels and wider scopes | `--depth 2..4`, `function`, `multi-repository` rejected with a clear message | `tests/test_engine.py` |
| REQ-016 | Recognise Bun lockfiles; list SQL as a language; report generated files committed to git | Pinning passes with `bun.lock`; SQL in inventory; tracked `__pycache__` reported | `tests/test_data_api_mcp.py` |
| REQ-017 | Assess PostgreSQL | Rules for row level security, policies, grants, SECURITY DEFINER, dynamic SQL; migration lint | `tests/test_data_api_mcp.py` |
| REQ-018 | Assess vector databases | pgvector table and search-function rules; client rules for insecure connections and unsafe index loading | `tests/test_data_api_mcp.py` |
| REQ-019 | Assess REST APIs | OpenAPI authentication/transport rules; code rules for CORS, TLS, JWT, injection | `tests/test_data_api_mcp.py` |
| REQ-020 | Assess MCP servers and configuration | Config rules for credentials, transport, unpinned packages; code rules for tool handlers | `tests/test_data_api_mcp.py` |
| REQ-021 | Guide developers towards standard practice (spec-driven development, documentation) | Missing practice yields a finding with why/how text; evidenced practice passes | `tests/test_guidance.py` |
| REQ-022 | Guidance is configurable | A team pack can extend, override, disable and add practices and remediation text | `tests/test_guidance.py::test_custom_pack_extends_overrides_disables_and_adds` |
| REQ-023 | Show which industry-standard categories the checks contribute evidence to | OWASP Top 10 and API Top 10 tables; coverage never reported as full | `tests/test_guidance.py::test_standards_coverage_is_never_reported_as_full` |
| REQ-024 | Evidence summary that can be handed to a reviewer | `eaf-evidence.md` with scope, checks, practices, standards, limitations | `tests/test_cli_report.py` |

## Open points

- REQ-010: the SWEAP control catalogue must come from its process owner.
- What IT accepts as evidence is not defined. REQ-023/024 provide a candidate format only.
- Vector databases other than pgvector are assessed only through client-code patterns.
