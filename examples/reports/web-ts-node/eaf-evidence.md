# EAF assessment evidence summary

> This report is an automated engineering quality indication produced by a prototype. A PASS result means only that the listed tools reported no findings above the policy thresholds for the assessed scope. It is NOT a security certification, does NOT establish ISO 26262 / ISO 21434 / ASPICE compliance, and is NOT an Audi IT or release approval. Checks marked NOT EXECUTED or NOT APPLICABLE provide no assurance.

## What was assessed

- **Scope:** `/home/user/Engg_assurance_framework/samples/web-ts-node` (repository, 7 files)
- **Revision:** `d3ac3632cb4c27b151e75284d893dc77037f42a9`
- **Source digest:** `sha256:526e4f92bda0df7af2d1826555bd2d47e6ab47f34b4b00b11b5b89bf3a2706bc`
- **When / with what:** 2026-11-14T09:00:31+00:00, eaf 0.2.0, Level 1 - static source inspection (read-only)
- **Policy:** `eaf-baseline@1.1.0` · **Guidance pack:** `eaf-practices@1.0.0` · **Criticality:** standard
- **Languages:** javascript (43 lines), typescript (30 lines)
- **Not assessed:** no unsupported languages detected
- **Dependency vulnerability lookups:** performed
- **Results digest:** `sha256:1fa667709b02b4b6cc6d3c32c0992fdec876d567327e33cc3c50aeef9f7bbc4c`

## Result

**Overall: FAIL** – 5 check(s) failed

Findings (not suppressed): 1 critical, 9 high, 9 medium, 22 low, 0 info; 0 suppressed with a recorded reason.

## Checks performed

| Status | Check | Tool and version | Findings c/h/m/l | Note |
|---|---|---|---|---|
| NOT APPLICABLE | Python static code quality (ruff) (`quality.ruff`) | ruff  | – | No python source files in scope |
| NOT APPLICABLE | C/C++ static analysis (cppcheck) (`quality.cppcheck`) | cppcheck  | – | No c/cpp source files in scope |
| FAIL | JavaScript static code quality (ESLint core rules) (`quality.eslint-js`) | eslint 10.1.0 | 0/1/4/6 | 1 finding(s) at or above 'high' severity |
| FAIL | TypeScript static code quality (ESLint core rules) (`quality.eslint-ts`) | eslint 10.1.0 | 0/1/2/2 | 1 finding(s) at or above 'high' severity |
| NOT APPLICABLE | PostgreSQL migration safety (squawk) (`quality.squawk`) | squawk  | – | No sql source files in scope |
| NOT APPLICABLE | Python security weaknesses (bandit) (`security.bandit`) | bandit  | – | No python source files in scope |
| NOT APPLICABLE | C/C++ risky API usage (flawfinder) (`security.flawfinder`) | flawfinder  | – | No c/cpp source files in scope |
| PASS | API, MCP, vector-store and web security patterns (semgrep, EAF rules) (`security.semgrep`) | semgrep 1.185.0 | 0/0/0/0 | No findings |
| NOT APPLICABLE | PostgreSQL / pgvector access-control rules (built-in) (`security.sql-postgres`) | eaf-builtin  | – | No sql source files in scope |
| NOT APPLICABLE | REST API contract: authentication and transport (OpenAPI, built-in) (`security.openapi`) | eaf-builtin  | – | No OpenAPI/Swagger document in scope |
| NOT APPLICABLE | MCP server configuration: credentials, transport, supply chain (built-in) (`security.mcp-config`) | eaf-builtin  | – | No MCP configuration file (.mcp.json, mcp.json, ...) in scope |
| FAIL | Hardcoded secrets in file contents (detect-secrets) (`secrets.detect-secrets`) | detect-secrets 1.5.0 | 0/1/0/0 | 1 finding(s) at or above 'medium' severity |
| FAIL | Credential / key files present in the source tree (`secrets.sensitive-files`) | eaf-builtin 0.2.0 | 0/1/0/0 | 1 finding(s) at or above 'high' severity |
| PASS | Dependencies are pinned / locked (`dependencies.pinning`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| NOT APPLICABLE | Python dependencies: known vulnerabilities (pip-audit) (`dependencies.pip-audit`) | pip-audit  | – | No Python dependency manifest in scope |
| FAIL | npm dependencies: known vulnerabilities (npm audit) (`dependencies.npm-audit`) | npm 10.9.9 | 1/5/0/3 | 6 finding(s) at or above 'high' severity |
| NOT APPLICABLE | Bun dependencies: known vulnerabilities (bun audit) (`dependencies.bun-audit`) | bun  | – | No bun.lock in scope |
| PASS | README present at scope root (`hygiene.readme`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| WARNING | License / copyright notice present (`hygiene.license`) | eaf-builtin 0.2.0 | 0/0/0/1 | 1 finding(s) at or above 'low' severity |
| WARNING | .gitignore present (`hygiene.gitignore`) | eaf-builtin 0.2.0 | 0/0/0/1 | 1 finding(s) at or above 'low' severity |
| WARNING | Automated tests exist for detected languages (`hygiene.tests-present`) | eaf-builtin 0.2.0 | 0/0/1/0 | 1 finding(s) at or above 'medium' severity |
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
| A02 Cryptographic Failures | partial | PASS | 0 | Key management, data-at-rest encryption, protocol configuration of deployed systems; C/C++ cryptography |
| A03 Injection | partial | FAIL | 2 | Data-flow across files or services; whether a flagged sink is reachable with untrusted data |
| A04 Insecure Design | partial | WARNING | 3 | Whether the design is secure. No tool evaluates this; it needs review |
| A05 Security Misconfiguration | partial | PASS | 0 | Configuration of deployed infrastructure, cloud resources, containers, headers at runtime |
| A06 Vulnerable and Outdated Components | partial | FAIL | 9 | C/C++ and vendored dependencies, container base images, yarn/pnpm/Poetry/uv lockfiles, licence compliance |
| A07 Identification and Authentication Failures | partial | FAIL | 2 | Session handling, password policy, MFA, token lifetime, the authentication implementation itself |
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
| API9 Improper Inventory Management | partial | WARNING | 1 | Whether the contract matches the deployed API; old versions still running |
| API10 Unsafe Consumption of APIs | partial | FAIL | 9 | Validation of third-party API responses |

## Critical and high findings

| Severity | Check | Rule | Location | Finding | How to fix |
|---|---|---|---|---|---|
| high | `quality.eslint-js` | `no-eval` | `src/server.js:10` | `eval` can be harmful. | Remove eval. Parse data with JSON.parse; for expressions use a dedicated, sandboxed parser. |
| high | `quality.eslint-ts` | `no-new-func` | `src/telemetry.ts:9` | The Function constructor is eval. | Do not build functions from strings; it is equivalent to eval. |
| high | `secrets.detect-secrets` | `Basic-Auth-Credentials` | `.env:2` | Possible secret: Basic Auth Credentials | Remove the value from source, rotate it (assume it is compromised once committed), and load it from the environment or a secret store. Add the file pattern to .gitignore. If it is a public/publishable identifier or a test fixture, add a suppression with that reason. |
| high | `secrets.sensitive-files` | `sensitive-file` | `.env` | File '.env' typically holds credentials or private key material and should not be stored in source control | Remove the value from source, rotate it (assume it is compromised once committed), and load it from the environment or a secret store. Add the file pattern to .gitignore. If it is a public/publishable identifier or a test fixture, add a suppression with that reason. |
| critical | `dependencies.npm-audit` | `GHSA-vh95-rmgr-6w4m` | `package-lock.json` | minimist (1.0.0 - 1.2.5): Prototype Pollution in minimist; Prototype Pollution in minimist | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.npm-audit` | `GHSA-35jh-r3h4-6jhm` | `package-lock.json` | lodash (<=4.17.23): Command Injection in lodash; Prototype Pollution in lodash; Regular Expression Denial of Service (ReDoS) in lodash | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.npm-audit` | `GHSA-9wv6-86v2-598j` | `package-lock.json` | path-to-regexp (<=0.1.12): path-to-regexp outputs backtracking regular expressions; path-to-regexp contains a ReDoS; path-to-regexp vulnerable to Regular Expression Denial of Service via multiple route parameters [transitive] | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.npm-audit` | `GHSA-hrpp-h998-j3pp` | `package-lock.json` | qs (<=6.15.4): qs vulnerable to Prototype Pollution; qs's arrayLimit bypass in its bracket notation allows DoS via memory exhaustion; qs: Denial of Service via Attacker Controlled isBuffer [transitive] | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.npm-audit` | `GHSA-qw6h-vgh9-j6wx` | `package-lock.json` | express (<=4.21.2 \|\| 5.0.0-alpha.1 - 5.0.0): express vulnerable to XSS via response.redirect(); Express.js Open Redirect in malformed URLs | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.npm-audit` | `GHSA-qwcr-r2fm-qrc7` | `package-lock.json` | body-parser (<=1.20.8): body-parser vulnerable to denial of service when url encoding is enabled; body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement; body-parser vulnerable to Denial of Service via trailing bytes after a compressed request body [transitive] | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |

## Limitations

- Level 1 inspects source text only: nothing is built, executed or tested.
- A PASS reflects the configured tools and thresholds only; absence of findings is not absence of defects.
- Engineering-practice checks establish that a document exists and has minimal substance. They do not judge whether it is correct, complete or followed.
- Standards coverage is partial by construction: a mapped category means some checks look for instances of that weakness class, not that the category is satisfied.
