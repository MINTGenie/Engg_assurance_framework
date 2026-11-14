"""PostgreSQL / pgvector rules, OpenAPI, MCP configuration, semgrep rules, Bun, git artefacts."""
import json
import shutil
import subprocess

import pytest
from conftest import SAMPLES, needs

from eaf.discovery import discover
from eaf.engine import Options, assess
from eaf.scanners.data_tools import split_sql

AMV = SAMPLES / "api-mcp-vector-service"


def check(root, check_id, **kw):
    report = assess(root, Options(only=[check_id], **kw))
    return next(c for c in report["checks"] if c["id"] == check_id)


def rules(c):
    return {f["rule_id"] for f in c["findings"]}


def by_rule(c, rule):
    return [f for f in c["findings"] if f["rule_id"] == rule]


# ------------------------------------------------------------------ discovery
def test_technologies_are_detected():
    tech = discover(AMV).technologies
    assert tech["api_frameworks"] == ["FastAPI"]
    assert tech["openapi_documents"] == ["openapi.json"]
    assert {"postgresql", "pgvector", "qdrant"} <= set(tech["data_stores"])
    assert tech["vector_stores"] == ["pgvector", "qdrant"]
    assert tech["mcp_packages"] == ["mcp"] and tech["mcp_config_files"] == [".mcp.json"]


def test_sql_is_a_supported_language_and_bun_lock_is_a_lockfile(tree):
    root = tree({"a.sql": "select 1;\n", "package.json": '{"dependencies": {"left-pad": "1.3.0"}}',
                 "bun.lock": "{}\n"})
    inv = discover(root)
    assert inv.supported_languages == ["sql"] and inv.unsupported_languages == []
    assert {"path": "bun.lock", "ecosystem": "npm", "kind": "lockfile"} in inv.manifests
    assert check(root, "dependencies.pinning")["status"] == "PASS"
    # without the lockfile the same manifest is reported
    (root / "bun.lock").unlink()
    assert rules(check(root, "dependencies.pinning")) == {"missing-npm-lockfile"}


# ------------------------------------------------------------------ SQL
def test_split_sql_respects_comments_strings_and_dollar_quotes():
    stmts = split_sql("""
        -- a comment; with semicolon
        create table t (a text default 'x;y'); /* block; */
        create function f() returns void as $body$ begin perform 1; perform 2; end; $body$ language plpgsql;
        select 1
    """)
    assert len(stmts) == 3
    assert stmts[0][1].startswith("create table") and "'x;y'" in stmts[0][1]
    assert "perform 2; end;" in stmts[1][1]
    assert stmts[0][0] == 3 and stmts[2][1] == "select 1"


def test_postgres_and_pgvector_rules_on_sample():
    c = check(AMV, "security.sql-postgres")
    assert c["status"] == "FAIL"
    assert {"PG002", "PG003", "PG004", "PG005", "PG006", "PG007", "VEC001", "VEC002", "VEC003"} == rules(c)
    assert by_rule(c, "PG004")[0]["message"].count("match_chunks") == 1   # safe_count is not flagged
    assert len(by_rule(c, "PG007")) == 1                                  # format() variant is not flagged
    assert "fixture-not-real-pw" not in json.dumps(c)
    assert "OWASP-2021-A01" in by_rule(c, "PG003")[0]["standards"]
    assert by_rule(c, "VEC002")[0]["guidance"]


def test_missing_rls_is_high_only_when_supabase_exposes_the_schema(tree):
    sql = "create table public.notes (id int primary key, body text);\n"
    plain = check(tree({"db/001.sql": sql}), "security.sql-postgres")
    assert rules(plain) == {"PG001-info"} and plain["status"] == "PASS"

    root = tree({"supabase/migrations/001.sql": sql + "create table public.ok (id int);\n"
                 "alter table public.ok enable row level security;\n"
                 "create policy own on public.ok for select using (auth.uid() = id);\n"})
    supa = check(root, "security.sql-postgres")
    assert supa["status"] == "FAIL"
    assert [f["message"].split("'")[1] for f in by_rule(supa, "PG001")] == ["notes"]


def test_rls_disable_and_drop_are_tracked(tree):
    root = tree({"supabase/migrations/001.sql":
                 "create table a (id int); alter table a enable row level security;\n"
                 "create policy p on a for select using (id = 1);\n"
                 "create table b (id int); drop table b;\n"
                 "alter table a disable row level security;\n"})
    c = check(root, "security.sql-postgres")
    assert rules(c) == {"PG008", "PG001"}
    assert all("'a'" in f["message"] for f in c["findings"])


@needs("squawk")
def test_squawk_runs_on_sample():
    c = check(AMV, "quality.squawk")
    assert c["status"] == "WARNING" and "syntax-error" not in rules(c)
    assert "require-concurrent-index-creation" in rules(c)


# ------------------------------------------------------------------ OpenAPI / MCP
def test_openapi_rules_on_sample():
    c = check(AMV, "security.openapi")
    assert rules(c) == {"OA002", "OA003", "OA005", "OA006"}
    unsecured = sorted(f["message"].split(": ")[1] for f in by_rule(c, "OA002"))
    assert unsecured == ["DELETE /documents/{doc_id}", "GET /health", "POST /search"]
    assert len(by_rule(c, "OA003")) == 1   # localhost server is not flagged


def test_openapi_without_any_security_and_yaml(tree):
    pytest.importorskip("yaml")
    root = tree({"api/openapi.yaml": "openapi: 3.0.0\ninfo: {title: t, version: '1'}\n"
                 "paths:\n  /x:\n    get:\n      responses: {'200': {description: ok}}\n"})
    c = check(root, "security.openapi")
    assert {"OA001", "OA002"} <= rules(c)
    assert check(tree({"a.py": "x = 1\n"}), "security.openapi")["status"] == "NOT_APPLICABLE"


def test_mcp_config_rules_on_sample_without_leaking_the_token():
    c = check(AMV, "security.mcp-config")
    assert c["status"] == "FAIL" and rules(c) == {"MCP001", "MCP002", "MCP003", "MCP004"}
    assert "fixture-token-not-real" not in json.dumps(c)
    # pinned package and ${env:...} reference are accepted
    assert not any("'github'" in f["message"] for f in c["findings"])


# ------------------------------------------------------------------ semgrep
@needs("semgrep")
def test_semgrep_rules_on_sample():
    c = check(AMV, "security.semgrep")
    assert c["status"] == "FAIL"
    assert rules(c) == {
        "py.cors-wildcard-with-credentials", "py.jwt-signature-not-verified",
        "py.tls-verification-disabled", "py.mcp-http-bound-to-all-interfaces",
        "py.mcp-tool-executes-command", "py.mcp-tool-reads-arbitrary-path",
        "py.vector-store-insecure-connection", "py.vector-index-unsafe-deserialization",
        "js.unsafe-html", "js.tls-verification-disabled", "js.sql-built-from-template",
        "js.jwt-signature-not-verified", "js.command-built-from-input", "js.hardcoded-password"}
    assert len(c["findings"]) == 14, "a 'correct example' in the fixture was flagged"
    assert any("self-test passed" in n for n in c["notes"])
    f = by_rule(c, "py.mcp-tool-executes-command")[0]
    assert f["cwe"] == "CWE-78" and f["guidance"] and "OWASP-2021-A03" in f["standards"]
    assert check(SAMPLES / "clean-python-lib", "security.semgrep")["status"] == "PASS"


# ------------------------------------------------------------------ Bun / git artefacts
def test_bun_audit_is_not_executed_offline(tree):
    root = tree({"package.json": '{"dependencies": {"left-pad": "1.3.0"}}', "bun.lock": "{}\n"})
    c = check(root, "dependencies.bun-audit", allow_network=False)
    assert c["status"] == "NOT_EXECUTED" and c["evidence"] == []
    assert check(SAMPLES / "clean-python-lib", "dependencies.bun-audit")["status"] == "NOT_APPLICABLE"


def test_tracked_generated_files_are_reported(tree):
    if not shutil.which("git"):
        pytest.skip("git not installed")
    root = tree({"pkg/mod.py": "x = 1\n", "pkg/__pycache__/mod.cpython-313.pyc": "bytes",
                 "node_modules/x/index.js": "x", "docs/readme.md": "ok"})
    git = ["git", "-C", str(root), "-c", "user.email=t@example.invalid", "-c", "user.name=t",
           "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run([*git, "add", "-f", "."], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "init"], check=True)
    c = check(root, "hygiene.tracked-artifacts")
    assert c["status"] == "WARNING"
    assert sorted(f["file"] for f in c["findings"]) == ["node_modules/", "pkg/__pycache__/"]
