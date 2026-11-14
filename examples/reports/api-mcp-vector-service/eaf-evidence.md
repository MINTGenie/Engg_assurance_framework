# EAF assessment evidence summary

> This report is an automated engineering quality indication produced by a prototype. A PASS result means only that the listed tools reported no findings above the policy thresholds for the assessed scope. It is NOT a security certification, does NOT establish ISO 26262 / ISO 21434 / ASPICE compliance, and is NOT an Audi IT or release approval. Checks marked NOT EXECUTED or NOT APPLICABLE provide no assurance.

## What was assessed

- **Scope:** `/home/user/Engg_assurance_framework/samples/api-mcp-vector-service` (repository, 13 files)
- **Revision:** `d3ac3632cb4c27b151e75284d893dc77037f42a9`
- **Source digest:** `sha256:7a66cfda3ebef8d4adc38e821f722872947cd7e82aaf5e16f367838776bc5352`
- **When / with what:** 2026-11-14T09:00:17+00:00, eaf 0.2.0, Level 1 - static source inspection (read-only)
- **Policy:** `eaf-baseline@1.1.0` · **Guidance pack:** `eaf-practices@1.0.0` · **Criticality:** standard
- **Languages:** python (72 lines), sql (69 lines), typescript (41 lines)
- **Not assessed:** no unsupported languages detected
- **Dependency vulnerability lookups:** performed
- **Results digest:** `sha256:9560d2f2976b53cbf383a31c8684b49bfd67829f27e946654a4bef1798a85a06`

## Result

**Overall: FAIL** – 6 check(s) failed

Findings (not suppressed): 0 critical, 37 high, 23 medium, 27 low, 2 info; 0 suppressed with a recorded reason.

## Checks performed

| Status | Check | Tool and version | Findings c/h/m/l | Note |
|---|---|---|---|---|
| PASS | Python static code quality (ruff) (`quality.ruff`) | ruff 0.16.9 | 0/0/0/0 | No findings |
| NOT APPLICABLE | C/C++ static analysis (cppcheck) (`quality.cppcheck`) | cppcheck  | – | No c/cpp source files in scope |
| NOT APPLICABLE | JavaScript static code quality (ESLint core rules) (`quality.eslint-js`) | eslint  | – | No javascript source files in scope |
| PASS | TypeScript static code quality (ESLint core rules) (`quality.eslint-ts`) | eslint 10.1.0 | 0/0/0/0 | No findings |
| WARNING | PostgreSQL migration safety (squawk) (`quality.squawk`) | squawk 2.71.0 | 0/0/0/11 | 11 finding(s) at or above 'low' severity |
| FAIL | Python security weaknesses (bandit) (`security.bandit`) | bandit 1.9.4 | 0/2/1/1 | 2 finding(s) at or above 'high' severity |
| NOT APPLICABLE | C/C++ risky API usage (flawfinder) (`security.flawfinder`) | flawfinder  | – | No c/cpp source files in scope |
| FAIL | API, MCP, vector-store and web security patterns (semgrep, EAF rules) (`security.semgrep`) | semgrep 1.185.0 | 0/7/7/0 | 7 finding(s) at or above 'high' severity |
| FAIL | PostgreSQL / pgvector access-control rules (built-in) (`security.sql-postgres`) | eaf-builtin 0.2.0 | 0/1/5/2 | 1 finding(s) at or above 'high' severity |
| WARNING | REST API contract: authentication and transport (OpenAPI, built-in) (`security.openapi`) | eaf-builtin 0.2.0 | 0/0/3/2 | 5 finding(s) at or above 'low' severity |
| FAIL | MCP server configuration: credentials, transport, supply chain (built-in) (`security.mcp-config`) | eaf-builtin 0.2.0 | 0/1/2/1 | 1 finding(s) at or above 'high' severity |
| FAIL | Hardcoded secrets in file contents (detect-secrets) (`secrets.detect-secrets`) | detect-secrets 1.5.0 | 0/0/2/0 | 2 finding(s) at or above 'medium' severity |
| PASS | Credential / key files present in the source tree (`secrets.sensitive-files`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| PASS | Dependencies are pinned / locked (`dependencies.pinning`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| FAIL | Python dependencies: known vulnerabilities (pip-audit) (`dependencies.pip-audit`) | pip-audit 2.10.1 | 0/26/0/0 | 26 finding(s) at or above 'high' severity |
| NOT EXECUTED | npm dependencies: known vulnerabilities (npm audit) (`dependencies.npm-audit`) | npm 10.9.9 | – | No package-lock.json next to package.json; auditing would require dependency resolution (yarn/pnpm lockfiles are not supported yet) |
| NOT APPLICABLE | Bun dependencies: known vulnerabilities (bun audit) (`dependencies.bun-audit`) | bun  | – | No bun.lock in scope |
| PASS | README present at scope root (`hygiene.readme`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| WARNING | License / copyright notice present (`hygiene.license`) | eaf-builtin 0.2.0 | 0/0/0/1 | 1 finding(s) at or above 'low' severity |
| WARNING | .gitignore present (`hygiene.gitignore`) | eaf-builtin 0.2.0 | 0/0/0/1 | 1 finding(s) at or above 'low' severity |
| WARNING | Automated tests exist for detected languages (`hygiene.tests-present`) | eaf-builtin 0.2.0 | 0/0/2/0 | 2 finding(s) at or above 'medium' severity |
| WARNING | CI pipeline configuration present (`hygiene.ci-config`) | eaf-builtin 0.2.0 | 0/0/0/1 | 1 finding(s) at or above 'low' severity |
| PASS | No large files or build artefacts in source (`hygiene.large-files`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |
| PASS | No generated files or caches under version control (`hygiene.tracked-artifacts`) | eaf-builtin 0.2.0 | 0/0/0/0 | No findings |

## Engineering practices

Evidence that a practice is followed (a document exists and has substance). Content is not reviewed.

| Status | Practice | Result |
|---|---|---|
| WARNING | A written specification exists | Not found: A written specification exists. Looked for: spec/*, specs/*, docs/spec*, docs/specs/*, docs/requirements*, requirements/*, docs/prd*, prd.md ... |
| WARNING | Specifications contain testable acceptance criteria | Not found: Specifications contain testable acceptance criteria. Looked for: spec/*, specs/*, docs/spec*, docs/specs/*, docs/requirements*, requirements/*, docs/prd*, prd.md ... |
| WARNING | README explains purpose, setup, usage and testing | README has no section about: usage / how to run |
| WARNING | Architecture or design decisions are documented | Not found: Architecture or design decisions are documented. Looked for: docs/architecture*, architecture.md, docs/design*, design.md, docs/adr/*, adr/*, docs/decisions/*, docs/arc42* ... |
| WARNING | Changes are recorded (changelog or release notes) | Not found: Changes are recorded (changelog or release notes). Looked for: changelog*, changes.md, history.md, release-notes*, releases.md, docs/changelog*, docs/release*, .changeset/* |
| WARNING | Contribution and review process is defined | Not found: Contribution and review process is defined. Looked for: contributing*, docs/contributing*, .github/pull_request_template*, .github/PULL_REQUEST_TEMPLATE/*, codeowners, .github/codeowners, docs/codeowners, .gitlab/merge_request_templates/* ... |
| WARNING | Security policy or threat model is documented | Not found: Security policy or threat model is documented. Looked for: security.md, .github/security.md, docs/security*, docs/threat*, threat-model*, docs/tara* |
| PASS | Documentation is updated together with the code | No findings |
| PASS | The REST API has a machine-readable contract (OpenAPI) | No findings |
| PASS | Database schema changes are versioned migrations | No findings |
| PASS | MCP servers and their tools are documented | No findings |
| WARNING | AI coding assistants have project instructions | Not found: AI coding assistants have project instructions. Looked for: agents.md, claude.md, .github/copilot-instructions.md, .github/instructions/*, .cursor/rules/*, .cursorrules, .windsurfrules, .clinerules ... |

## OWASP Top 10 (2021) – evidence contributed

No category is fully covered by static inspection. "partial" = some checks look for instances.

| Category | Level 1 evidence | Status | Findings | Not covered |
|---|---|---|---|---|
| A01 Broken Access Control | partial | FAIL | 5 | Authorisation logic in application code; object-level access checks; anything decided at runtime |
| A02 Cryptographic Failures | partial | FAIL | 5 | Key management, data-at-rest encryption, protocol configuration of deployed systems; C/C++ cryptography |
| A03 Injection | partial | FAIL | 8 | Data-flow across files or services; whether a flagged sink is reachable with untrusted data |
| A04 Insecure Design | partial | WARNING | 4 | Whether the design is secure. No tool evaluates this; it needs review |
| A05 Security Misconfiguration | partial | FAIL | 3 | Configuration of deployed infrastructure, cloud resources, containers, headers at runtime |
| A06 Vulnerable and Outdated Components | partial | FAIL | 26 | C/C++ and vendored dependencies, container base images, yarn/pnpm/Poetry/uv lockfiles, licence compliance |
| A07 Identification and Authentication Failures | partial | FAIL | 11 | Session handling, password policy, MFA, token lifetime, the authentication implementation itself |
| A08 Software and Data Integrity Failures | partial | FAIL | 2 | Build pipeline integrity, artefact signing, update mechanisms |
| A09 Security Logging and Monitoring Failures | none | – | 0 | Not assessed at Level 1 |
| A10 Server-Side Request Forgery (SSRF) | none | – | 0 | Not assessed at Level 1 (needs data-flow analysis) |

## OWASP API Security Top 10 (2023) – evidence contributed

No category is fully covered by static inspection. "partial" = some checks look for instances.

| Category | Level 1 evidence | Status | Findings | Not covered |
|---|---|---|---|---|
| API1 Broken Object Level Authorization | partial | FAIL | 3 | Object-level checks in API handlers |
| API2 Broken Authentication | partial | FAIL | 6 | The authentication implementation; endpoints that are not in an OpenAPI document |
| API3 Broken Object Property Level Authorization | none | – | 0 | Not assessed at Level 1 |
| API4 Unrestricted Resource Consumption | partial | WARNING | 1 | Actual rate limits, payload limits, timeouts, cost controls |
| API5 Broken Function Level Authorization | partial | WARNING | 3 | Role checks in handlers; admin functions not described in the document |
| API6 Unrestricted Access to Sensitive Business Flows | none | – | 0 | Not assessable by static tools |
| API7 Server Side Request Forgery | none | – | 0 | Not assessed at Level 1 |
| API8 Security Misconfiguration | partial | FAIL | 7 | Deployed gateway, TLS and header configuration |
| API9 Improper Inventory Management | partial | PASS | 0 | Whether the contract matches the deployed API; old versions still running |
| API10 Unsafe Consumption of APIs | partial | FAIL | 28 | Validation of third-party API responses |

## Critical and high findings

| Severity | Check | Rule | Location | Finding | How to fix |
|---|---|---|---|---|---|
| high | `security.bandit` | `B501` | `app/api.py:23` | Call to requests with verify=False disabling SSL certificate checks, security issue. [request_with_no_cert_validation] |  |
| high | `security.bandit` | `B602` | `app/mcp_server.py:14` | subprocess call with shell=True identified, security issue. [subprocess_popen_with_shell_equals_true] | Pass the command as an argument list without a shell, and validate any value that comes from outside the process. |
| high | `security.semgrep` | `py.jwt-signature-not-verified` | `app/api.py:16` | JWT is decoded without verifying its signature | Verify the signature with the issuer's key and pin the accepted algorithms (algorithms=["RS256"]). |
| high | `security.semgrep` | `py.tls-verification-disabled` | `app/api.py:23` | TLS certificate verification is disabled for an outbound HTTP call | Remove verify=False. If an internal CA is used, pass its bundle (verify="/path/ca.pem"). |
| high | `security.semgrep` | `py.mcp-tool-executes-command` | `app/mcp_server.py:14` | MCP tool runs a shell command or evaluates code; its arguments are chosen by an AI model | Treat every tool argument as untrusted. Remove shell/eval, call a fixed program with an argument list, and validate arguments against an allow-list. If command execution is the tool's purpose, run it in a sandbox and require human approval. |
| high | `security.semgrep` | `py.vector-index-unsafe-deserialization` | `app/search.py:12` | Vector index is loaded with pickle deserialisation enabled | Only load index files you created and whose integrity you verify (checksum/signature); prefer a store that does not rely on pickle. A tampered index file executes code on load. |
| high | `security.semgrep` | `js.tls-verification-disabled` | `web/src/client.ts:9` | TLS certificate verification is disabled | Remove rejectUnauthorized false / NODE_TLS_REJECT_UNAUTHORIZED=0 and trust the internal CA explicitly (ca option or NODE_EXTRA_CA_CERTS). |
| high | `security.semgrep` | `js.jwt-signature-not-verified` | `web/src/client.ts:23` | JWT is accepted without verifying its signature | Use jwt.verify with the issuer's key and an explicit algorithms list that does not contain "none". jwt.decode does not check the signature. |
| high | `security.semgrep` | `js.command-built-from-input` | `web/src/client.ts:28` | Shell command is built from a template string or concatenation | Use execFile/spawn with an argument array and no shell, and validate each argument against an allow-list. |
| high | `security.sql-postgres` | `PG006` | `db/migrations/001_init.sql:37` | Role password is written as a literal in a SQL file | Create roles without a password in migrations and set credentials through the secret store / deployment tooling. Rotate this one. |
| high | `security.mcp-config` | `MCP001` | `.mcp.json` | MCP server 'fleet-tools': headers.Authorization contains a literal credential | Reference the secret (for example "${env:NAME}" or an input prompt) instead of storing it, rotate the exposed value, and use a token scoped to what the tools need. |
| high | `dependencies.pip-audit` | `GHSA-pxh4-856f-4h89` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (GHSA-pxh4-856f-4h89); fix versions: 2.14.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2024-115` | `requirements.txt` | langchain-community 0.2.16 has a known vulnerability (CVE-2024-8309, GHSA-45pg-36p6-83v9, PYSEC-2026-1507); fix versions: 0.2.19 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2025-183` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2025-45768); fix versions: none listed | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-120` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-32597, GHSA-752w-5fwx-jx9f); fix versions: 2.12.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-1515` | `requirements.txt` | langchain-community 0.2.16 has a known vulnerability (CVE-2025-6984, GHSA-pc6w-59fv-rh23); fix versions: 0.3.27 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-1616` | `requirements.txt` | mcp 1.2.0 has a known vulnerability (CVE-2025-53366, GHSA-3qhf-m339-9g5v); fix versions: 1.9.4 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-1617` | `requirements.txt` | mcp 1.2.0 has a known vulnerability (CVE-2025-66416, GHSA-9h52-p55h-vw2f); fix versions: 1.23.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-1618` | `requirements.txt` | mcp 1.2.0 has a known vulnerability (CVE-2025-53365, GHSA-j975-95f5-7wqh); fix versions: 1.10.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-175` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-48522, GHSA-993g-76c3-p5m4); fix versions: 2.13.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-176` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-48523, GHSA-jq35-7prp-9v3f); fix versions: 2.12.1, 2.13.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-177` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-48524, GHSA-fhv5-28vv-h8m8); fix versions: 2.13.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-178` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-48525, GHSA-w7vc-732c-9m39); fix versions: 2.13.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-179` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-48526, GHSA-xgmm-8j9v-c9wx); fix versions: 2.13.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-1872` | `requirements.txt` | requests 2.32.3 has a known vulnerability (CVE-2024-47081, GHSA-9hjg-9r4m-mvj7); fix versions: 2.32.4 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-2275` | `requirements.txt` | requests 2.32.3 has a known vulnerability (CVE-2026-25645, GHSA-gc5v-m9x4-r6x2); fix versions: 2.33.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-3482` | `requirements.txt` | mcp 1.2.0 has a known vulnerability (CVE-2026-52869, GHSA-jpw9-pfvf-9f58); fix versions: 1.27.2 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-3483` | `requirements.txt` | mcp 1.2.0 has a known vulnerability (CVE-2026-59950, GHSA-vj7q-gjh5-988w); fix versions: 1.28.1 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-4140` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-101917, GHSA-2gx3-rcp4-g85q); fix versions: 2.14.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-4141` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-101918, GHSA-42vr-xj54-vc7v); fix versions: 2.15.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-4144` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-102267, GHSA-9v7f-9g4p-ffgj); fix versions: 2.14.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-4145` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-102268, GHSA-ffc3-869f-jxw9); fix versions: 2.14.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-4147` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-102269, GHSA-hxm8-2xgr-2p9m); fix versions: 2.14.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-4148` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-102270, GHSA-jwrc-g2q2-pq5p); fix versions: 2.14.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-4149` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-102271, GHSA-p4g4-x82p-q773); fix versions: 2.14.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-4152` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-102274, GHSA-w6j9-cwv2-h6wq); fix versions: 2.14.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |
| high | `dependencies.pip-audit` | `PYSEC-2026-4183` | `requirements.txt` | pyjwt 2.9.0 has a known vulnerability (CVE-2026-102275, GHSA-x33g-cr3x-6449); fix versions: 2.15.0 | Upgrade to a fixed version. If no fix exists, check whether the vulnerable function is reachable, document the decision, and track it. |

## Limitations

- Level 1 inspects source text only: nothing is built, executed or tested.
- A PASS reflects the configured tools and thresholds only; absence of findings is not absence of defects.
- Engineering-practice checks establish that a document exists and has minimal substance. They do not judge whether it is correct, complete or followed.
- Standards coverage is partial by construction: a mapped category means some checks look for instances of that weakness class, not that the category is satisfied.
