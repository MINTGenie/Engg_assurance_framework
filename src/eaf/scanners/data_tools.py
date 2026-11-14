"""Database adapters: built-in PostgreSQL / pgvector security rules and squawk (migrations).

The built-in rules read SQL text statically. They know nothing about the live database:
objects created outside the scanned files, or changed by hand, are invisible to them.
"""
from __future__ import annotations

import json
import re

from eaf.models import Finding, Severity
from eaf.runner import find_tool
from eaf.scanners.base import ScanContext, ScanNotExecuted, ScannerAdapter, ScanOutput, chunks


def split_sql(text: str) -> list[tuple[int, str]]:
    """Split SQL into (start_line, statement). Comments are removed; string literals and
    dollar-quoted bodies are kept intact so that ';' inside them does not split."""
    out, buf, i, n, line, start = [], [], 0, len(text), 1, 1
    while i < n:
        ch = text[i]
        two = text[i:i + 2]
        if two == "--":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if two == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            line += text.count("\n", i, j)
            i = j
            continue
        if ch == "'":
            j = i + 1
            while j < n:
                if text[j] == "'" and text[j:j + 2] == "''":
                    j += 2
                    continue
                if text[j] == "'":
                    break
                j += 1
            chunk = text[i:j + 1]
        elif ch == "$":
            m = re.match(r"\$[A-Za-z_]*\$", text[i:])
            if m:
                end = text.find(m.group(0), i + len(m.group(0)))
                end = n if end == -1 else end + len(m.group(0))
                chunk = text[i:end]
            else:
                chunk = ch
        elif ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                out.append((start, stmt))
            buf, i = [], i + 1
            start = line
            continue
        else:
            chunk = ch
        if not buf and chunk.isspace():
            line += chunk.count("\n")
            start = line
            i += len(chunk)
            continue
        buf.append(chunk)
        line += chunk.count("\n")
        i += len(chunk)
    stmt = "".join(buf).strip()
    if stmt:
        out.append((start, stmt))
    return out


_IDENT = r'((?:"[^"]+"|[\w$]+)(?:\.(?:"[^"]+"|[\w$]+))?)'
RE_CREATE_TABLE = re.compile(r"^create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?" + _IDENT, re.I)
RE_DROP_TABLE = re.compile(r"^drop\s+table\s+(?:if\s+exists\s+)?" + _IDENT, re.I)
RE_ALTER_RLS = re.compile(r"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?" + _IDENT +
                          r"\s+(enable|disable|force)\s+row\s+level\s+security", re.I)
RE_ALTER_ADD_VECTOR = re.compile(r"^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?" + _IDENT, re.I)
RE_POLICY = re.compile(r"^create\s+policy\s+(?:\"[^\"]+\"|\S+)\s+on\s+" + _IDENT, re.I)
RE_POLICY_FOR = re.compile(r"\bfor\s+(all|select|insert|update|delete)\b", re.I)
RE_POLICY_TO = re.compile(r"\bto\s+([\w\s,\"]+?)(?=\s+(?:using|with\s+check)\b|$)", re.I | re.S)
RE_TRUE_USING = re.compile(r"\busing\s*\(\s*true\s*\)", re.I)
RE_TRUE_CHECK = re.compile(r"\bwith\s+check\s*\(\s*true\s*\)", re.I)
RE_FUNCTION = re.compile(r"^create\s+(?:or\s+replace\s+)?function\s+" + _IDENT, re.I)
RE_GRANT = re.compile(r"^grant\s+(.+?)\s+on\s+(.+?)\s+to\s+(.+)$", re.I | re.S)
RE_ROLE_PASSWORD = re.compile(r"^(?:create|alter)\s+(?:role|user)\s+.*\bpassword\s+'[^']+'", re.I | re.S)
RE_EXECUTE = re.compile(r"\bexecute\b(?!\s+(?:function|procedure)\b)([^;]*)", re.I)
RE_VECTOR_COL = re.compile(r"\b(?:vector|halfvec|sparsevec)\s*\(\s*\d+\s*\)", re.I)
RE_VECTOR_INDEX = re.compile(r"^create\s+(?:unique\s+)?index\s+.*?\bon\s+(?:only\s+)?" + _IDENT +
                             r".*?\busing\s+(hnsw|ivfflat)\b", re.I | re.S)
RE_SIMILARITY = re.compile(r"<=>|<->|<#>")
WRITE_PRIVS = re.compile(r"\b(all|insert|update|delete|truncate)\b", re.I)
OPEN_ROLES = re.compile(r"\b(anon|public)\b", re.I)

G_RLS = ("Enable row level security on every table reachable through the API "
         "(ALTER TABLE ... ENABLE ROW LEVEL SECURITY) and add policies that restrict rows to "
         "their owner or tenant, e.g. USING (auth.uid() = user_id).")
G_POLICY = ("Replace the unconditional 'true' with a predicate that ties the row to the caller "
            "(owner, tenant or role). If public access is intended, restrict it to SELECT and "
            "document why.")
G_DEFINER = ("Add 'SET search_path = <schema>, pg_temp' (or '') to every SECURITY DEFINER "
             "function, and prefer SECURITY INVOKER unless elevated rights are required.")
G_VECTOR = ("Embeddings can reveal the text they were computed from. Protect vector tables "
            "with the same row-level rules as the source data and filter similarity searches "
            "by tenant/user inside the query.")


def _norm(name: str) -> tuple[str | None, str]:
    parts = [p.strip('"').lower() for p in name.split(".")]
    return (parts[0], parts[1]) if len(parts) == 2 else (None, parts[0])


class PostgresRulesAdapter(ScannerAdapter):
    id = "security.sql-postgres"
    title = "PostgreSQL / pgvector access-control rules (built-in)"
    category = "security"
    languages = ("sql",)

    def _f(self, rule, sev, msg, file, line, cwe=None, guidance=None, standards=()):
        return Finding(check_id=self.id, rule_id=rule, severity=sev, message=msg, file=file,
                       line=line, cwe=cwe, guidance=guidance, standards=list(standards),
                       confidence="heuristic")

    def scan(self, ctx: ScanContext) -> ScanOutput:  # noqa: C901 - rule table in one place
        files = sorted(self.target_files(ctx))
        supabase = "supabase" in ctx.inventory.technologies.get("data_stores", [])
        out = ScanOutput(files_examined=len(files), notes=[
            "Static rules over SQL files, evaluated in file-name order (migration order). "
            "The live database is not inspected.",
            "Supabase/PostgREST detected: tables in the public schema are treated as reachable "
            "with the public API key." if supabase else
            "No Supabase/PostgREST usage detected: missing row level security is reported as "
            "informational because access control may be enforced in the application."])
        tables: dict[str, dict] = {}
        add = out.findings.append

        for rel in files:
            text = (ctx.root / rel).read_text(encoding="utf-8", errors="replace")
            for line, stmt in split_sql(text):
                flat = re.sub(r"\s+", " ", stmt)
                if m := RE_CREATE_TABLE.match(flat):
                    schema, name = _norm(m.group(1))
                    if schema in (None, "public") and not re.match(r"create\s+temp", flat, re.I):
                        tables[name] = {"file": rel, "line": line, "rls": False, "policies": 0,
                                        "vector": bool(RE_VECTOR_COL.search(flat)), "ann": False}
                elif m := RE_DROP_TABLE.match(flat):
                    tables.pop(_norm(m.group(1))[1], None)
                elif m := RE_ALTER_RLS.match(flat):
                    name, action = _norm(m.group(1))[1], m.group(2).lower()
                    if name in tables:
                        tables[name]["rls"] = action != "disable"
                    if action == "disable":
                        add(self._f("PG008", Severity.HIGH, f"Row level security is disabled on "
                                    f"table '{name}'", rel, line, "CWE-285", G_RLS))
                elif (m := RE_ALTER_ADD_VECTOR.match(flat)) and RE_VECTOR_COL.search(flat):
                    name = _norm(m.group(1))[1]
                    if name in tables:
                        tables[name]["vector"] = True
                elif m := RE_POLICY.match(flat):
                    name = _norm(m.group(1))[1]
                    if name in tables:
                        tables[name]["policies"] += 1
                    cmd = (RE_POLICY_FOR.search(flat) or [None, "all"])[1].lower()
                    roles = (RE_POLICY_TO.search(flat) or [None, "public (default)"])[1].strip()
                    using_true, check_true = RE_TRUE_USING.search(flat), RE_TRUE_CHECK.search(flat)
                    if cmd == "select" and using_true:
                        if OPEN_ROLES.search(roles):
                            add(self._f("PG003-read", Severity.LOW, f"Policy on '{name}' lets role "
                                        f"'{roles}' read every row (USING (true))", rel, line,
                                        "CWE-285", G_POLICY))
                    elif using_true or check_true:
                        add(self._f("PG003", Severity.MEDIUM, f"Policy on '{name}' allows {cmd.upper()} "
                                    f"for role '{roles}' without any row condition "
                                    f"({'USING' if using_true else 'WITH CHECK'} (true))",
                                    rel, line, "CWE-285", G_POLICY))
                elif m := RE_FUNCTION.match(flat):
                    fname = _norm(m.group(1))[1]
                    definer = re.search(r"\bsecurity\s+definer\b", flat, re.I)
                    if definer and not re.search(r"\bset\s+search_path\b", flat, re.I):
                        add(self._f("PG004", Severity.MEDIUM, f"SECURITY DEFINER function "
                                    f"'{fname}' does not pin search_path", rel, line, "CWE-427",
                                    G_DEFINER))
                    if definer and RE_SIMILARITY.search(flat):
                        add(self._f("VEC002", Severity.MEDIUM, f"Vector similarity function '{fname}' "
                                    "is SECURITY DEFINER and therefore bypasses row level security "
                                    "on the embeddings table", rel, line, "CWE-285", G_VECTOR,
                                    ["OWASP-LLM-2025-LLM08"]))
                    for em in RE_EXECUTE.finditer(flat):
                        frag = em.group(1)
                        if "||" in frag and not re.search(r"\bformat\s*\(|quote_(ident|literal|nullable)", frag, re.I):
                            add(self._f("PG007", Severity.MEDIUM, f"Function '{fname}' builds dynamic "
                                        "SQL by concatenation (EXECUTE ... || ...)", rel, line, "CWE-89",
                                        "Use format() with %I / %L, or EXECUTE ... USING parameters."))
                            break
                elif m := RE_GRANT.match(flat):
                    privs, target, grantee = m.groups()
                    if WRITE_PRIVS.search(privs) and OPEN_ROLES.search(grantee) and \
                            not re.match(r"\s*(function|procedure|routine|schema|sequence)\b", target, re.I):
                        add(self._f("PG005", Severity.MEDIUM, f"Write privileges ({privs.strip()[:40]}) "
                                    f"granted to '{grantee.strip()[:40]}' on {target.strip()[:60]}",
                                    rel, line, "CWE-732",
                                    "Grant only the privileges each role needs; do not grant write "
                                    "access to anonymous or PUBLIC roles."))
                elif RE_ROLE_PASSWORD.match(flat):
                    add(self._f("PG006", Severity.HIGH, "Role password is written as a literal in a "
                                "SQL file", rel, line, "CWE-798",
                                "Create roles without a password in migrations and set credentials "
                                "through the secret store / deployment tooling. Rotate this one."))
                elif m := RE_VECTOR_INDEX.match(flat):
                    name = _norm(m.group(1))[1]
                    if name in tables:
                        tables[name]["ann"] = True

        for name, t in sorted(tables.items()):
            what = "vector/embedding table" if t["vector"] else "table"
            if not t["rls"]:
                if supabase:
                    add(self._f("PG001", Severity.HIGH, f"Row level security is not enabled on "
                                f"{what} '{name}'; with Supabase it is readable and writable "
                                "through the public API", t["file"], t["line"], "CWE-285",
                                G_RLS + (" " + G_VECTOR if t["vector"] else "")))
                elif t["vector"]:
                    add(self._f("VEC003", Severity.LOW, f"Vector table '{name}' has no row level "
                                "security; tenant isolation depends entirely on application code",
                                t["file"], t["line"], "CWE-285", G_VECTOR, ["OWASP-LLM-2025-LLM08"]))
                else:
                    add(self._f("PG001-info", Severity.INFO, f"Row level security is not enabled on "
                                f"table '{name}'", t["file"], t["line"], "CWE-285", G_RLS))
            elif t["policies"] == 0:
                add(self._f("PG002", Severity.LOW, f"Row level security is enabled on '{name}' but "
                            "no policy is defined in the scanned files; only privileged roles can "
                            "access it", t["file"], t["line"], None,
                            "If the table is used by clients, add explicit policies; if it is "
                            "server-only, state that in a comment in the migration."))
            if t["vector"] and not t["ann"]:
                add(self._f("VEC001", Severity.INFO, f"Vector table '{name}' has no HNSW/IVFFlat index; "
                            "similarity search will scan the whole table", t["file"], t["line"], None,
                            "Add an approximate-nearest-neighbour index (USING hnsw or ivfflat) "
                            "matching the distance operator used in queries."))
        n_vec = sum(1 for t in tables.values() if t["vector"])
        out.notes.append(f"{len(tables)} table(s) in the public schema tracked, {n_vec} with vector "
                         f"columns, {sum(1 for t in tables.values() if t['rls'])} with row level "
                         "security enabled.")
        return out


class SquawkAdapter(ScannerAdapter):
    id = "quality.squawk"
    title = "PostgreSQL migration safety (squawk)"
    category = "code_quality"
    tool = "squawk"
    languages = ("sql",)

    def scan(self, ctx: ScanContext) -> ScanOutput:
        files = self.target_files(ctx)
        out = ScanOutput(files_examined=len(files), notes=[
            "squawk checks whether migrations are safe to apply to a live PostgreSQL database "
            "(locks, rewrites, re-runnability). For a database that is not yet in production "
            "these findings matter less."])
        sev = {"Error": Severity.MEDIUM, "Warning": Severity.LOW}
        for batch in chunks(files, 200):
            res = ctx.run(self.id, [find_tool(self.tool), "--reporter", "json",
                                    *[ctx.abs(f) for f in batch]])
            out.evidence.append(res.evidence)
            try:
                data = json.loads(res.stdout)
            except json.JSONDecodeError as exc:
                raise ScanNotExecuted(f"squawk failed (exit {res.exit_code}): "
                                      f"{(res.stderr or res.stdout).strip()[:300]}") from exc
            for v in data:
                msg = v.get("message", "")
                if v.get("help"):
                    msg += f" ({v['help']})"
                out.findings.append(Finding(
                    check_id=self.id, rule_id=v.get("rule_name", "squawk"),
                    severity=sev.get(v.get("level", "Warning"), Severity.LOW), message=msg,
                    file=ctx.rel(v.get("file", "")), line=int(v.get("line", 0)) + 1))
        return out
