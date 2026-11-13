"""Adapter tests. Severity mapping is tested directly; tool integration is tested against
the sample repositories and skipped when a scanner is not installed."""
import json
import shutil
import subprocess

from conftest import SAMPLES, needs

from eaf.engine import Options, assess
from eaf.models import Severity
from eaf.scanners import all_adapters
from eaf.scanners.c_cpp_tools import flawfinder_severity
from eaf.scanners.python_tools import ruff_severity


def check(sample, check_id, **kw):
    report = assess(SAMPLES / sample, Options(only=[check_id], **kw))
    return next(c for c in report["checks"] if c["id"] == check_id)


def rules(c):
    return {f["rule_id"] for f in c["findings"]}


def test_adapter_ids_are_unique_and_categorised():
    adapters = all_adapters()
    assert len({a.id for a in adapters}) == len(adapters)
    assert {a.category for a in adapters} == {"code_quality", "security", "secrets",
                                              "dependencies", "hygiene"}
    for lang in ("python", "c", "cpp", "javascript", "typescript"):
        assert any(lang in a.languages and a.tool for a in adapters), lang


def test_severity_mappings():
    assert ruff_severity("F821") is Severity.HIGH
    assert ruff_severity("invalid-syntax") is Severity.HIGH
    assert ruff_severity("B006") is Severity.MEDIUM
    assert ruff_severity("F401") is Severity.LOW
    assert [flawfinder_severity(n) for n in (0, 1, 3, 4, 5)] == [
        Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.HIGH]


@needs("ruff")
def test_ruff_on_python_sample():
    c = check("vuln-python-service", "quality.ruff")
    assert c["status"] == "FAIL" and {"F821", "B006", "F401"} <= rules(c)
    assert c["scanner_version"] and c["evidence"][0]["exit_code"] == 1
    assert check("clean-python-lib", "quality.ruff")["status"] == "PASS"


@needs("bandit")
def test_bandit_on_python_sample_and_redaction():
    c = check("vuln-python-service", "security.bandit")
    assert c["status"] == "FAIL" and {"B602", "B608", "B307", "B506", "B301"} <= rules(c)
    assert "Tr0ub4dor" not in json.dumps(c), "hardcoded password value leaked into the report"
    assert check("clean-python-lib", "security.bandit")["status"] == "PASS"


@needs("cppcheck")
def test_cppcheck_on_c_sample():
    c = check("embedded-c-cpp", "quality.cppcheck")
    assert c["status"] == "FAIL"
    assert {"arrayIndexOutOfBounds", "memleak", "uninitMemberVar"} <= rules(c)
    # headers must not be analysed as standalone units (false 'unused member' findings)
    assert "unusedStructMember" not in rules(c)


@needs("flawfinder")
def test_flawfinder_on_c_sample():
    c = check("embedded-c-cpp", "security.flawfinder")
    assert c["status"] == "FAIL"
    assert {"FF1014:gets", "FF1001:strcpy"} <= rules(c)


@needs("eslint")
def test_eslint_js_on_node_sample():
    c = check("web-ts-node", "quality.eslint-js")
    assert c["status"] == "FAIL" and {"no-eval", "no-dupe-keys", "use-isnan"} <= rules(c)
    assert all(f["file"].endswith(".js") for f in c["findings"])


@needs("eslint")
def test_eslint_ts_runs_or_is_explicitly_not_executed():
    c = check("web-ts-node", "quality.eslint-ts")
    if c["status"] == "NOT_EXECUTED":
        assert "@typescript-eslint/parser" in c["reason"]
    else:
        assert c["status"] == "FAIL" and {"no-new-func", "no-debugger"} <= rules(c)


@needs("detect-secrets")
def test_detect_secrets_finds_fixture_secrets_without_leaking_them():
    c = check("vuln-python-service", "secrets.detect-secrets")
    assert c["status"] == "FAIL" and "AWS-Access-Key" in rules(c)
    assert any("self-test passed" in n for n in c["notes"])
    assert "AKIA" + "IOSFODNN7EXAMPLE" not in json.dumps(c)
    assert check("clean-python-lib", "secrets.detect-secrets")["status"] == "PASS"


def test_builtin_checks_on_samples():
    assert check("web-ts-node", "secrets.sensitive-files")["status"] == "FAIL"
    pin = check("vuln-python-service", "dependencies.pinning")
    assert pin["status"] == "WARNING" and rules(pin) == {"unpinned-python-dependency"}
    assert check("vuln-python-service", "hygiene.tests-present")["status"] == "WARNING"
    assert check("embedded-c-cpp", "hygiene.tests-present")["status"] == "PASS"
    assert check("embedded-c-cpp", "dependencies.pinning")["status"] == "NOT_APPLICABLE"
    for cid in ("hygiene.readme", "hygiene.license", "hygiene.gitignore", "hygiene.ci-config",
                "hygiene.tests-present", "dependencies.pinning"):
        assert check("clean-python-lib", cid)["status"] == "PASS", cid


def test_dependency_audits_are_not_executed_offline():
    for sample, cid in (("vuln-python-service", "dependencies.pip-audit"),
                        ("web-ts-node", "dependencies.npm-audit")):
        c = check(sample, cid, allow_network=False)
        assert c["status"] == "NOT_EXECUTED" and c["evidence"] == []


def test_untrusted_repository_code_is_never_executed(tree, tmp_path):
    """Files that would run code if a build tool, test runner, linter config loader or git
    hook touched them. Each would create the marker file."""
    marker = tmp_path / "EXECUTED"
    py = f"open({str(marker)!r}, 'w').write('x')\n"
    js = f"require('fs').writeFileSync({json.dumps(str(marker))}, 'x');\nmodule.exports = [];\n"
    root = tree({
        "setup.py": py, "conftest.py": py, "noxfile.py": py, "pkg/__init__.py": py,
        "eslint.config.js": js, "eslint.config.cjs": js, ".eslintrc.js": js, "index.js": js,
        "package.json": json.dumps({"name": "x", "version": "1.0.0", "scripts": {
            "preinstall": f"touch {marker}", "postinstall": f"touch {marker}",
            "prepare": f"touch {marker}"}}),
        "Makefile": f"all:\n\ttouch {marker}\n",
        "CMakeLists.txt": f'execute_process(COMMAND touch "{marker}")\n',
        "main.c": "int main(void) { return 0; }\n",
        ".bandit": "[bandit]\n", "pyproject.toml": "[tool.ruff]\nselect = []\n",
    })
    if shutil.which("git"):
        git = ["git", "-C", str(root), "-c", "user.email=t@example.invalid", "-c", "user.name=t",
               "-c", "commit.gpgsign=false"]
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-q", "-m", "init"], check=True)
        # planted after the commit so only the assessment could trigger them
        hook = root / ".git" / "hooks" / "post-index-change"
        hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
        hook.chmod(0o755)
        with open(root / ".git" / "config", "a", encoding="utf-8") as fh:
            fh.write(f"[core]\n\tfsmonitor = touch {marker}\n")
        # sanity: an unhardened git call WOULD execute the planted program
        subprocess.run(["git", "-C", str(root), "status"], capture_output=True)
        assert marker.exists(), "fixture does not exercise the git execution path"
        marker.unlink()
    report = assess(root, Options())
    assert not marker.exists(), "assessed repository code was executed"
    assert report["assessment"]["scope"]["source_tree_unmodified"] is True
