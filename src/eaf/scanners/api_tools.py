"""API-surface adapters: OpenAPI documents and MCP (Model Context Protocol) configuration."""
from __future__ import annotations

import json
import re

from eaf.models import Finding, Severity
from eaf.scanners.base import ScanContext, ScanNotExecuted, ScannerAdapter, ScanOutput

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "options", "head", "trace")
_LOCAL = re.compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|host\.docker\.internal)([:/]|$)", re.I)
MAX_PER_RULE = 25


class OpenApiAdapter(ScannerAdapter):
    id = "security.openapi"
    title = "REST API contract: authentication and transport (OpenAPI, built-in)"
    category = "security"

    def target_files(self, ctx: ScanContext) -> list[str]:
        return ctx.inventory.technologies.get("openapi_documents", [])

    def applicable(self, ctx: ScanContext) -> tuple[bool, str]:
        if self.target_files(ctx):
            return True, ""
        return False, "No OpenAPI/Swagger document in scope"

    def _load(self, ctx: ScanContext, rel: str):
        text = (ctx.root / rel).read_text(encoding="utf-8", errors="replace")
        if rel.lower().endswith(".json"):
            return json.loads(text)
        try:
            import yaml  # optional dependency
        except ImportError as exc:
            raise ScanNotExecuted("PyYAML is not installed; YAML OpenAPI documents cannot be "
                                  "read (pip install pyyaml)") from exc
        return yaml.safe_load(text)

    def _f(self, rule, sev, msg, rel, cwe, guidance, standards):
        return Finding(check_id=self.id, rule_id=rule, severity=sev, message=msg, file=rel,
                       cwe=cwe, guidance=guidance, standards=list(standards))

    def scan(self, ctx: ScanContext) -> ScanOutput:  # noqa: C901
        out = ScanOutput(notes=["Checks the API description only. Endpoints that exist in code "
                                "but not in the document, and the actual enforcement of the "
                                "declared security, are not verified."])
        for rel in self.target_files(ctx):
            try:
                doc = self._load(ctx, rel)
            except ScanNotExecuted:
                raise
            except Exception as exc:  # malformed document
                out.findings.append(self._f("OA000", Severity.MEDIUM, f"Document cannot be parsed: "
                                            f"{type(exc).__name__}", rel, None,
                                            "Fix the syntax so tools and reviewers can read the contract.", []))
                continue
            if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc):
                continue
            out.files_examined += 1
            v2 = "swagger" in doc
            schemes = (doc.get("securityDefinitions") if v2
                       else (doc.get("components") or {}).get("securitySchemes")) or {}
            global_sec = doc.get("security")
            if not schemes:
                out.findings.append(self._f(
                    "OA001", Severity.MEDIUM, "No security scheme is defined for this API", rel,
                    "CWE-306", "Define securitySchemes (OAuth2 / OpenID Connect / bearer JWT) and "
                    "apply them globally with a top-level 'security' entry.",
                    ["OWASP-API-2023-API2"]))
            for name, s in schemes.items():
                s = s or {}
                if (s.get("type") == "basic") or (s.get("type") == "http" and str(s.get("scheme", "")).lower() == "basic"):
                    out.findings.append(self._f(
                        "OA004", Severity.LOW, f"Security scheme '{name}' uses HTTP Basic "
                        "authentication", rel, "CWE-287",
                        "Prefer token-based authentication (OAuth2 / OIDC) with short-lived tokens.",
                        ["OWASP-API-2023-API2"]))
                if s.get("type") == "apiKey" and s.get("in") == "query":
                    out.findings.append(self._f(
                        "OA005", Severity.LOW, f"Security scheme '{name}' sends the API key in the "
                        "query string, where it is logged by proxies and servers", rel, "CWE-598",
                        "Send credentials in a header.", ["OWASP-API-2023-API2"]))
            urls = [s.get("url", "") for s in doc.get("servers", []) if isinstance(s, dict)]
            if v2 and "http" in (doc.get("schemes") or []) and "https" not in (doc.get("schemes") or []):
                urls.append("http://" + str(doc.get("host", "")))
            for url in urls:
                if url.lower().startswith("http://") and not _LOCAL.match(url):
                    out.findings.append(self._f(
                        "OA003", Severity.MEDIUM, f"Server URL uses plain HTTP: {url[:80]}", rel,
                        "CWE-319", "Serve the API over HTTPS only.", ["OWASP-API-2023-API8"]))
            unsecured, any_429, n_ops = [], False, 0
            for path, item in (doc.get("paths") or {}).items():
                if not isinstance(item, dict):
                    continue
                for method in HTTP_METHODS:
                    op = item.get(method)
                    if not isinstance(op, dict):
                        continue
                    n_ops += 1
                    if "429" in (op.get("responses") or {}):
                        any_429 = True
                    sec = op.get("security", global_sec)
                    if not sec or sec == [{}]:
                        unsecured.append(f"{method.upper()} {path}")
            if schemes or unsecured:
                for op_name in unsecured[:MAX_PER_RULE]:
                    write = not op_name.startswith(("GET", "HEAD", "OPTIONS"))
                    out.findings.append(self._f(
                        "OA002", Severity.MEDIUM if write else Severity.LOW,
                        f"Operation has no security requirement: {op_name}", rel, "CWE-306",
                        "Add a 'security' requirement, or mark the operation as intentionally "
                        "public in its description and suppress this finding with that reason.",
                        ["OWASP-API-2023-API2", "OWASP-API-2023-API5"]))
                if len(unsecured) > MAX_PER_RULE:
                    out.notes.append(f"{rel}: {len(unsecured) - MAX_PER_RULE} further unsecured "
                                     "operations not listed.")
            if n_ops and not any_429:
                out.findings.append(self._f(
                    "OA006", Severity.INFO, "No operation documents a 429 (rate limit) response", rel,
                    "CWE-770", "Define rate limits and document the 429 response.",
                    ["OWASP-API-2023-API4"]))
            out.notes.append(f"{rel}: {n_ops} operation(s), {len(schemes)} security scheme(s).")
        return out


_SECRET_KEY = re.compile(r"(key|token|secret|password|passwd|authorization|credential|pat)\b|_pat$", re.I)
_PLACEHOLDER = re.compile(r"^\s*$|\$\{|\$\(|^\$[A-Z_]|^<.*>$|^(your|my|xxx|changeme|todo|example|dummy|placeholder|redacted|\*+)|^env:|^input:", re.I)
_ARG_SECRET = re.compile(r"(api[-_]?key|token|secret|password)[=:](?!\$)\S{8,}|bearer\s+(?!\$)[A-Za-z0-9._-]{16,}", re.I)
_LAUNCHERS = {"npx": 0, "bunx": 0, "pnpx": 0, "uvx": 0, "pipx": 1}
_PINNED = re.compile(r"^(@[\w.-]+/)?[\w.-]+(@\d[\w.+-]*|==\d[\w.+-]*)$")


class McpConfigAdapter(ScannerAdapter):
    id = "security.mcp-config"
    title = "MCP server configuration: credentials, transport, supply chain (built-in)"
    category = "security"

    def target_files(self, ctx: ScanContext) -> list[str]:
        return ctx.inventory.technologies.get("mcp_config_files", [])

    def applicable(self, ctx: ScanContext) -> tuple[bool, str]:
        if self.target_files(ctx):
            return True, ""
        return False, "No MCP configuration file (.mcp.json, mcp.json, ...) in scope"

    def _f(self, rule, sev, msg, rel, cwe, guidance, standards=()):
        return Finding(check_id=self.id, rule_id=rule, severity=sev, message=msg, file=rel,
                       cwe=cwe, guidance=guidance, standards=list(standards))

    def scan(self, ctx: ScanContext) -> ScanOutput:  # noqa: C901
        out = ScanOutput(notes=[
            "Checks configuration files only. Whether an MCP server authenticates callers, "
            "validates tool input or limits what its tools may do is not verifiable at Level 1.",
            "Secret values are never written to the report."])
        for rel in self.target_files(ctx):
            try:
                doc = json.loads((ctx.root / rel).read_text(encoding="utf-8", errors="replace"))
            except ValueError:
                out.notes.append(f"{rel}: not valid JSON, skipped")
                continue
            servers = (doc.get("mcpServers") or doc.get("servers") or {}) if isinstance(doc, dict) else {}
            if not isinstance(servers, dict):
                continue
            out.files_examined += 1
            for name, cfg in servers.items():
                if not isinstance(cfg, dict):
                    continue
                for section in ("env", "headers"):
                    for key, value in (cfg.get(section) or {}).items():
                        if _SECRET_KEY.search(key) and isinstance(value, str) and \
                                len(value) >= 8 and not _PLACEHOLDER.search(value):
                            out.findings.append(self._f(
                                "MCP001", Severity.HIGH, f"MCP server '{name}': {section}.{key} "
                                "contains a literal credential", rel, "CWE-798",
                                "Reference the secret (for example \"${env:NAME}\" or an input "
                                "prompt) instead of storing it, rotate the exposed value, and use "
                                "a token scoped to what the tools need.", ["OWASP-2021-A07"]))
                args = [str(a) for a in (cfg.get("args") or [])]
                if any(_ARG_SECRET.search(a) for a in args):
                    out.findings.append(self._f(
                        "MCP001", Severity.HIGH, f"MCP server '{name}': a command argument contains "
                        "a literal credential", rel, "CWE-798",
                        "Pass credentials through the environment from a secret store.",
                        ["OWASP-2021-A07"]))
                url = str(cfg.get("url") or cfg.get("serverUrl") or "")
                if url.lower().startswith("http://") and not _LOCAL.match(url):
                    out.findings.append(self._f(
                        "MCP002", Severity.MEDIUM, f"MCP server '{name}' is reached over plain HTTP "
                        f"({url[:60]})", rel, "CWE-319",
                        "Use HTTPS for remote MCP servers; tool calls and tokens are otherwise "
                        "readable and modifiable in transit.", ["OWASP-2021-A02"]))
                command = str(cfg.get("command") or "").rsplit("/", 1)[-1]
                if command in _LAUNCHERS:
                    pkgs = [a for a in args[_LAUNCHERS[command]:] if not a.startswith("-")]
                    pkg = pkgs[0] if pkgs else ""
                    if pkg and not _PINNED.match(pkg) and not pkg.startswith((".", "/")):
                        out.findings.append(self._f(
                            "MCP003", Severity.MEDIUM, f"MCP server '{name}' runs '{command} {pkg}' "
                            "without a pinned version; whatever is published under that name "
                            "next will be downloaded and executed", rel, "CWE-829",
                            "Pin the exact version (pkg@1.2.3), or install the server from an "
                            "internal registry and run the installed binary.", ["OWASP-2021-A08"]))
                if command in ("sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh") and \
                        any(a in ("-c", "/c", "-Command") for a in args):
                    out.findings.append(self._f(
                        "MCP004", Severity.LOW, f"MCP server '{name}' is started through a shell "
                        "command line", rel, "CWE-78",
                        "Start the server binary directly with an argument list."))
            out.notes.append(f"{rel}: {len(servers)} MCP server(s) configured.")
        return out
