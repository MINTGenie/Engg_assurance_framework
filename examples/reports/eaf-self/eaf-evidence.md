# EAF assessment evidence summary

> This report is an automated engineering quality indication produced by a prototype. A PASS result means only that the listed tools reported no findings above the policy thresholds for the assessed scope. It is NOT a security certification, does NOT establish ISO 26262 / ISO 21434 / ASPICE compliance, and is NOT an Audi IT or release approval. Checks marked NOT EXECUTED or NOT APPLICABLE provide no assurance.

## What was assessed

- **Scope:** `/home/user/Engg_assurance_framework` (repository, 52 files)
- **Revision:** `46a728af97c02dd2581b9420b864ec61c58c6b75`
- **Source digest:** `sha256:20b4ee328c772c509ce41c1ca2d1a7e56e66338cb556e1748cd826a25b29d9f0`
- **When / with what:** 2026-11-14T09:01:08+00:00, eaf 0.2.0, Level 1 - static source inspection (read-only)
- **Policy:** `eaf-baseline@1.1.0` · **Guidance pack:** `eaf-practices@1.0.0` · **Criticality:** standard
- **Languages:** javascript (93 lines), python (4725 lines)
- **Not assessed:** no unsupported languages detected
- **Dependency vulnerability lookups:** performed
- **Results digest:** `sha256:87c9a06aa8c3794fca4e81563de3934e74e908d0696b5d3fddd9ab1536fafd1b`

## Result

**Overall: WARNING** – 5 check(s) raised warnings

Findings (not suppressed): 0 critical, 0 high, 0 medium, 14 low, 0 info; 43 suppressed with a recorded reason.

## Checks performed

| Status | Check | Tool and version | Findings c/h/m/l | Note |
|---|---|---|---|---|
| WARNING | Python static code quality (ruff) (`quality.ruff`) | ruff 0.16.9 | 0/0/0/10 | 10 finding(s) at or above 'low' severity |
| NOT APPLICABLE | C/C++ static analysis (cppcheck) (`quality.cppcheck`) | cppcheck  | – | No c/cpp source files in scope |
| PASS | JavaScript static code quality (ESLint core rules) (`quality.eslint-js`) | eslint 10.1.0 | 0/0/0/0 | No findings |
| NOT APPLICABLE | TypeScript static code quality (ESLint core rules) (`quality.eslint-ts`) | eslint  | – | No typescript source files in scope |
| NOT APPLICABLE | PostgreSQL migration safety (squawk) (`quality.squawk`) | squawk  | – | No sql source files in scope |
| PASS | Python security weaknesses (bandit) (`security.bandit`) | bandit 1.9.4 | 0/0/0/0 | No findings (41 suppressed) |
| NOT APPLICABLE | C/C++ risky API usage (flawfinder) (`security.flawfinder`) | flawfinder  | – | No c/cpp source files in scope |
| PASS | API, MCP, vector-store and web security patterns (semgrep, EAF rules) (`security.semgrep`) | semgrep 1.185.0 | 0/0/0/0 | No findings |
| NOT APPLICABLE | PostgreSQL / pgvector access-control rules (built-in) (`security.sql-postgres`) | eaf-builtin  | – | No sql source files in scope |
| NOT APPLICABLE | REST API contract: authentication and transport (OpenAPI, built-in) (`security.openapi`) | eaf-builtin  | – | No OpenAPI/Swagger document in scope |
| NOT APPLICABLE | MCP server configuration: credentials, transport, supply chain (built-in) (`security.mcp-config`) | eaf-builtin  | – | No MCP configuration file (.mcp.json, mcp.json, ...) in scope |
| PASS | Hardcoded secrets in file contents (detect-secrets) (`secrets.detect-secrets`) | detect-secrets 1.5.0 | 0/0/0/0 | No findings (1 suppressed) |
| PASS | Credential / key files present in the source tree (`secrets.sensitive-files`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| PASS | Dependencies are pinned / locked (`dependencies.pinning`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| NOT EXECUTED | Python dependencies: known vulnerabilities (pip-audit) (`dependencies.pip-audit`) | pip-audit 2.10.1 | – | Only requirements*.txt files are audited at Level 1; resolving pyproject.toml/setup.py dependencies would require running build code |
| NOT APPLICABLE | npm dependencies: known vulnerabilities (npm audit) (`dependencies.npm-audit`) | npm  | – | No package.json in scope |
| NOT APPLICABLE | Bun dependencies: known vulnerabilities (bun audit) (`dependencies.bun-audit`) | bun  | – | No bun.lock in scope |
| PASS | README present at scope root (`hygiene.readme`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| WARNING | License / copyright notice present (`hygiene.license`) | eaf-builtin 0.2.0 | 0/0/0/1 | 1 finding(s) at or above 'low' severity |
| PASS | .gitignore present (`hygiene.gitignore`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| PASS | Automated tests exist for detected languages (`hygiene.tests-present`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings (1 suppressed) |
| WARNING | CI pipeline configuration present (`hygiene.ci-config`) | eaf-builtin 0.2.0 | 0/0/0/1 | 1 finding(s) at or above 'low' severity |
| PASS | No large files or build artefacts in source (`hygiene.large-files`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| PASS | No generated files or caches under version control (`hygiene.tracked-artifacts`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |

## Engineering practices

Evidence that a practice is followed (a document exists and has substance). Content is not reviewed.

| Status | Practice | Result |
|---|---|---|
| PASS | A written specification exists | No findings |
| PASS | Specifications contain testable acceptance criteria | No findings |
| PASS | README explains purpose, setup, usage and testing | No findings |
| PASS | Architecture or design decisions are documented | No findings |
| PASS | Changes are recorded (changelog or release notes) | No findings |
| WARNING | Contribution and review process is defined | Not found: Contribution and review process is defined. Looked for: contributing*, docs/contributing*, .github/pull_request_template*, .github/PULL_REQUEST_TEMPLATE/*, codeowners, .github/codeowners, docs/codeowners, .gitlab/merge_request_templates/* ... |
| WARNING | Security policy or threat model is documented | Not found: Security policy or threat model is documented. Looked for: security.md, .github/security.md, docs/security*, docs/threat*, threat-model*, docs/tara* |
| PASS | Documentation is updated together with the code | No findings |
| NOT APPLICABLE | The REST API has a machine-readable contract (OpenAPI) | Practice applies only when: api (not met: api) |
| NOT APPLICABLE | Database schema changes are versioned migrations | Practice applies only when: database (not met: database) |
| NOT APPLICABLE | MCP servers and their tools are documented | Practice applies only when: mcp (not met: mcp) |
| PASS | AI coding assistants have project instructions | No findings |

## OWASP Top 10 (2021) – evidence contributed

No category is fully covered by static inspection. "partial" = some checks look for instances.

| Category | Level 1 evidence | Status | Findings | Not covered |
|---|---|---|---|---|
| A01 Broken Access Control | partial | PASS | 0 | Authorisation logic in application code; object-level access checks; anything decided at runtime |
| A02 Cryptographic Failures | partial | PASS | 0 | Key management, data-at-rest encryption, protocol configuration of deployed systems; C/C++ cryptography |
| A03 Injection | partial | PASS | 0 | Data-flow across files or services; whether a flagged sink is reachable with untrusted data |
| A04 Insecure Design | partial | WARNING | 1 | Whether the design is secure. No tool evaluates this; it needs review |
| A05 Security Misconfiguration | partial | PASS | 0 | Configuration of deployed infrastructure, cloud resources, containers, headers at runtime |
| A06 Vulnerable and Outdated Components | partial | NOT EXECUTED | 0 | C/C++ and vendored dependencies, container base images, yarn/pnpm/Poetry/uv lockfiles, licence compliance |
| A07 Identification and Authentication Failures | partial | PASS | 0 | Session handling, password policy, MFA, token lifetime, the authentication implementation itself |
| A08 Software and Data Integrity Failures | partial | PASS | 0 | Build pipeline integrity, artefact signing, update mechanisms |
| A09 Security Logging and Monitoring Failures | none | – | 0 | Not assessed at Level 1 |
| A10 Server-Side Request Forgery (SSRF) | none | – | 0 | Not assessed at Level 1 (needs data-flow analysis) |

## OWASP API Security Top 10 (2023) – evidence contributed

No category is fully covered by static inspection. "partial" = some checks look for instances.

| Category | Level 1 evidence | Status | Findings | Not covered |
|---|---|---|---|---|
| API1 Broken Object Level Authorization | none | – | 0 | Object-level checks in API handlers |
| API2 Broken Authentication | partial | PASS | 0 | The authentication implementation; endpoints that are not in an OpenAPI document |
| API3 Broken Object Property Level Authorization | none | – | 0 | Not assessed at Level 1 |
| API4 Unrestricted Resource Consumption | none | – | 0 | Actual rate limits, payload limits, timeouts, cost controls |
| API5 Broken Function Level Authorization | none | – | 0 | Role checks in handlers; admin functions not described in the document |
| API6 Unrestricted Access to Sensitive Business Flows | none | – | 0 | Not assessable by static tools |
| API7 Server Side Request Forgery | none | – | 0 | Not assessed at Level 1 |
| API8 Security Misconfiguration | partial | PASS | 0 | Deployed gateway, TLS and header configuration |
| API9 Improper Inventory Management | none | – | 0 | Whether the contract matches the deployed API; old versions still running |
| API10 Unsafe Consumption of APIs | partial | NOT EXECUTED | 0 | Validation of third-party API responses |

## Limitations

- Level 1 inspects source text only: nothing is built, executed or tested.
- A PASS reflects the configured tools and thresholds only; absence of findings is not absence of defects.
- Engineering-practice checks establish that a document exists and has minimal substance. They do not judge whether it is correct, complete or followed.
- Standards coverage is partial by construction: a mapped category means some checks look for instances of that weakness class, not that the category is satisfied.
