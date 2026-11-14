# EAF assessment evidence summary

> This report is an automated engineering quality indication produced by a prototype. A PASS result means only that the listed tools reported no findings above the policy thresholds for the assessed scope. It is NOT a security certification, does NOT establish ISO 26262 / ISO 21434 / ASPICE compliance, and is NOT an Audi IT or release approval. Checks marked NOT EXECUTED or NOT APPLICABLE provide no assurance.

## What was assessed

- **Scope:** `/home/user/Engg_assurance_framework/samples/vuln-python-service` (repository, 6 files)
- **Revision:** `d3ac3632cb4c27b151e75284d893dc77037f42a9`
- **Source digest:** `sha256:b64590752c10b0c2235e314f520fc86fbbd640228c80a39254fe761cc3245cfa`
- **When / with what:** 2026-11-14T09:00:45+00:00, eaf 0.2.0, Level 1 - static source inspection (read-only)
- **Policy:** `sweap-placeholder@0.0.1` · **Guidance pack:** `eaf-practices@1.0.0` · **Criticality:** standard
- **Languages:** python (77 lines)
- **Not assessed:** no unsupported languages detected
- **Dependency vulnerability lookups:** NOT performed (network disabled)
- **Results digest:** `sha256:fe7111367ff20a78251f294a7b981eab5fe4d6c8bedc89091b59d9b853cea93f`

## Result

**Overall: FAIL** – 3 check(s) failed

Findings (not suppressed): 0 critical, 4 high, 13 medium, 19 low, 0 info; 0 suppressed with a recorded reason.

## Checks performed

| Status | Check | Tool and version | Findings c/h/m/l | Note |
|---|---|---|---|---|
| FAIL | Python static code quality (ruff) (`quality.ruff`) | ruff 0.16.9 | 0/1/1/3 | 1 finding(s) at or above 'high' severity |
| NOT APPLICABLE | C/C++ static analysis (cppcheck) (`quality.cppcheck`) | cppcheck  | – | No c/cpp source files in scope |
| NOT APPLICABLE | JavaScript static code quality (ESLint core rules) (`quality.eslint-js`) | eslint  | – | No javascript source files in scope |
| NOT APPLICABLE | TypeScript static code quality (ESLint core rules) (`quality.eslint-ts`) | eslint  | – | No typescript source files in scope |
| NOT APPLICABLE | PostgreSQL migration safety (squawk) (`quality.squawk`) | squawk  | – | No sql source files in scope |
| FAIL | Python security weaknesses (bandit) (`security.bandit`) | bandit 1.9.4 | 0/2/5/5 | 2 finding(s) at or above 'high' severity |
| NOT APPLICABLE | C/C++ risky API usage (flawfinder) (`security.flawfinder`) | flawfinder  | – | No c/cpp source files in scope |
| PASS | API, MCP, vector-store and web security patterns (semgrep, EAF rules) (`security.semgrep`) | semgrep 1.185.0 | 0/0/0/0 | No findings |
| NOT APPLICABLE | PostgreSQL / pgvector access-control rules (built-in) (`security.sql-postgres`) | eaf-builtin  | – | No sql source files in scope |
| NOT APPLICABLE | REST API contract: authentication and transport (OpenAPI, built-in) (`security.openapi`) | eaf-builtin  | – | No OpenAPI/Swagger document in scope |
| NOT APPLICABLE | MCP server configuration: credentials, transport, supply chain (built-in) (`security.mcp-config`) | eaf-builtin  | – | No MCP configuration file (.mcp.json, mcp.json, ...) in scope |
| FAIL | Hardcoded secrets in file contents (detect-secrets) (`secrets.detect-secrets`) | detect-secrets 1.5.0 | 0/1/2/0 | 3 finding(s) at or above 'medium' severity |
| PASS | Credential / key files present in the source tree (`secrets.sensitive-files`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| WARNING | Dependencies are pinned / locked (`dependencies.pinning`) | eaf-builtin 0.2.0 | 0/0/2/0 | 2 finding(s) at or above 'low' severity |
| NOT EXECUTED | Python dependencies: known vulnerabilities (pip-audit) (`dependencies.pip-audit`) | pip-audit 2.10.1 | – | Requires a network lookup of dependency names/versions; network access is disabled by default (enable with --allow-network) |
| NOT APPLICABLE | npm dependencies: known vulnerabilities (npm audit) (`dependencies.npm-audit`) | npm  | – | No package.json in scope |
| NOT APPLICABLE | Bun dependencies: known vulnerabilities (bun audit) (`dependencies.bun-audit`) | bun  | – | No bun.lock in scope |
| PASS | README present at scope root (`hygiene.readme`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| WARNING | License / copyright notice present (`hygiene.license`) | eaf-builtin 0.2.0 | 0/0/0/1 | 1 finding(s) at or above 'low' severity |
| WARNING | .gitignore present (`hygiene.gitignore`) | eaf-builtin 0.2.0 | 0/0/0/1 | 1 finding(s) at or above 'low' severity |
| WARNING | Automated tests exist for detected languages (`hygiene.tests-present`) | eaf-builtin 0.2.0 | 0/0/1/0 | 1 finding(s) at or above 'low' severity |
| WARNING | CI pipeline configuration present (`hygiene.ci-config`) | eaf-builtin 0.2.0 | 0/0/0/1 | 1 finding(s) at or above 'low' severity |
| PASS | No large files or build artefacts in source (`hygiene.large-files`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| PASS | No generated files or caches under version control (`hygiene.tracked-artifacts`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |

## Engineering practices

Evidence that a practice is followed (a document exists and has substance). Content is not reviewed.

| Status | Practice | Result |
|---|---|---|
| WARNING | A written specification exists | Not found: A written specification exists. Looked for: spec/*, specs/*, docs/spec*, docs/specs/*, docs/requirements*, requirements/*, docs/prd*, prd.md ... |
| WARNING | Specifications contain testable acceptance criteria | Not found: Specifications contain testable acceptance criteria. Looked for: spec/*, specs/*, docs/spec*, docs/specs/*, docs/requirements*, requirements/*, docs/prd*, prd.md ... |
| WARNING | README explains purpose, setup, usage and testing | README has no section about: setup / installation |
| WARNING | Architecture or design decisions are documented | Not found: Architecture or design decisions are documented. Looked for: docs/architecture*, architecture.md, docs/design*, design.md, docs/adr/*, adr/*, docs/decisions/*, docs/arc42* ... |
| WARNING | Changes are recorded (changelog or release notes) | Not found: Changes are recorded (changelog or release notes). Looked for: changelog*, changes.md, history.md, release-notes*, releases.md, docs/changelog*, docs/release*, .changeset/* |
| WARNING | Contribution and review process is defined | Not found: Contribution and review process is defined. Looked for: contributing*, docs/contributing*, .github/pull_request_template*, .github/PULL_REQUEST_TEMPLATE/*, codeowners, .github/codeowners, docs/codeowners, .gitlab/merge_request_templates/* ... |
| WARNING | Security policy or threat model is documented | Not found: Security policy or threat model is documented. Looked for: security.md, .github/security.md, docs/security*, docs/threat*, threat-model*, docs/tara* |
| PASS | Documentation is updated together with the code | No findings |
| WARNING | The REST API has a machine-readable contract (OpenAPI) | Not found: The REST API has a machine-readable contract (OpenAPI). Looked for: openapi*.json, openapi*.yaml, openapi*.yml, swagger*.json, swagger*.yaml, swagger*.yml, *.openapi.json, *.openapi.yaml ... |
| NOT APPLICABLE | Database schema changes are versioned migrations | Practice applies only when: database (not met: database) |
| NOT APPLICABLE | MCP servers and their tools are documented | Practice applies only when: mcp (not met: mcp) |
| WARNING | AI coding assistants have project instructions | Not found: AI coding assistants have project instructions. Looked for: agents.md, claude.md, .github/copilot-instructions.md, .github/instructions/*, .cursor/rules/*, .cursorrules, .windsurfrules, .clinerules ... |

## OWASP Top 10 (2021) – evidence contributed

No category is fully covered by static inspection. "partial" = some checks look for instances.

| Category | Level 1 evidence | Status | Findings | Not covered |
|---|---|---|---|---|
| A01 Broken Access Control | partial | PASS | 0 | Authorisation logic in application code; object-level access checks; anything decided at runtime |
| A02 Cryptographic Failures | partial | FAIL | 1 | Key management, data-at-rest encryption, protocol configuration of deployed systems; C/C++ cryptography |
| A03 Injection | partial | FAIL | 5 | Data-flow across files or services; whether a flagged sink is reachable with untrusted data |
| A04 Insecure Design | partial | WARNING | 3 | Whether the design is secure. No tool evaluates this; it needs review |
| A05 Security Misconfiguration | partial | FAIL | 1 | Configuration of deployed infrastructure, cloud resources, containers, headers at runtime |
| A06 Vulnerable and Outdated Components | partial | WARNING | 2 | C/C++ and vendored dependencies, container base images, yarn/pnpm/Poetry/uv lockfiles, licence compliance |
| A07 Identification and Authentication Failures | partial | FAIL | 5 | Session handling, password policy, MFA, token lifetime, the authentication implementation itself |
| A08 Software and Data Integrity Failures | partial | FAIL | 6 | Build pipeline integrity, artefact signing, update mechanisms |
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
| API9 Improper Inventory Management | partial | WARNING | 1 | Whether the contract matches the deployed API; old versions still running |
| API10 Unsafe Consumption of APIs | partial | NOT EXECUTED | 0 | Validation of third-party API responses |

## Critical and high findings

| Severity | Check | Rule | Location | Finding | How to fix |
|---|---|---|---|---|---|
| high | `quality.ruff` | `F821` | `app/server.py:65` | Undefined name `default_payload` |  |
| high | `security.bandit` | `B602` | `app/server.py:34` | subprocess call with shell=True identified, security issue. [subprocess_popen_with_shell_equals_true] | Pass the command as an argument list without a shell, and validate any value that comes from outside the process. |
| high | `security.bandit` | `B324` | `app/server.py:53` | Use of weak MD5 hash for security. Consider usedforsecurity=False [hashlib] | Use SHA-256 or stronger. If the hash is not used for security, pass usedforsecurity=False. |
| high | `secrets.detect-secrets` | `AWS-Access-Key` | `app/config.py:6` | Possible secret: AWS Access Key | Remove the value from source, rotate it (assume it is compromised once committed), and load it from the environment or a secret store. Add the file pattern to .gitignore. If it is a public/publishable identifier or a test fixture, add a suppression with that reason. |

## Limitations

- Level 1 inspects source text only: nothing is built, executed or tested.
- A PASS reflects the configured tools and thresholds only; absence of findings is not absence of defects.
- Engineering-practice checks establish that a document exists and has minimal substance. They do not judge whether it is correct, complete or followed.
- Standards coverage is partial by construction: a mapped category means some checks look for instances of that weakness class, not that the category is satisfied.
- Known-vulnerability lookups for dependencies were not performed (network disabled).
