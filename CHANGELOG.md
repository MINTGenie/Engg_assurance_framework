# Changelog

Format: Keep a Changelog. Versioning: Semantic Versioning.

## 0.2.0 – 2026-11-14

### Added
- Engineering practice checks (`practice.*`) driven by a versioned, configurable guidance
  pack: specification, acceptance criteria, README sections, architecture, changelog,
  contribution process, security policy, documentation freshness, API contract, data model,
  MCP documentation, AI assistant instructions.
- Fix guidance and standard references (CWE, OWASP) on findings; `eaf guidance` command;
  `--guidance` option and `[assessment] guidance` profile key.
- Standards coverage tables for OWASP Top 10 (2021) and OWASP API Security Top 10 (2023).
- `eaf-evidence.md` evidence summary (`--format md`).
- PostgreSQL / pgvector rules (`security.sql-postgres`), squawk migration lint
  (`quality.squawk`), OpenAPI rules (`security.openapi`), MCP configuration rules
  (`security.mcp-config`), semgrep adapter with 17 bundled rules (`security.semgrep`),
  Bun audit (`dependencies.bun-audit`), tracked generated files (`hygiene.tracked-artifacts`).
- Detection of API frameworks, OpenAPI documents, data stores, vector stores and MCP usage.
- Sample `samples/api-mcp-vector-service`; EAF's own specification in `specs/`.

### Changed
- Policy `eaf-baseline` 1.0.0 → 1.1.0 (new checks and controls; glob keys such as `practice.*`).
- Report schema 1.0 → 1.1 (`guidance`, `standards` on findings; `standards_coverage`;
  `inventory.technologies`; `assessment.guidance`).
- SQL is now an assessed language; `bun.lock` counts as a lockfile.
- `.vscode/` is no longer excluded from scope (it can hold `mcp.json`).

### Fixed
- False "no lockfile" finding for projects using Bun.
- Generated files committed inside excluded directories were invisible.

## 0.1.0 – 2026-11-13

- First prototype: CLI, 17 checks for Python, C/C++, JavaScript/TypeScript, secrets,
  dependencies and hygiene; JSON/HTML reports; policies; context profile; samples.
