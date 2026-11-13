"""Engine behaviour with fake adapters: no external tools required."""
import pytest

from eaf.engine import AssessmentError, Options, assess
from eaf.models import Finding, Severity
from eaf.scanners.base import ScanNotExecuted, ScannerAdapter, ScanOutput


class Fake(ScannerAdapter):
    category = "code_quality"

    def __init__(self, id, severities=(), languages=(), tool=None, network=False, error=None,
                 min_depth=1):
        self.id, self.title = id, id
        self.languages, self.tool, self.requires_network = languages, tool, network
        self._severities, self._error, self.min_depth = severities, error, min_depth

    def scan(self, ctx):
        if self._error:
            raise self._error
        return ScanOutput(findings=[
            Finding(check_id=self.id, rule_id=f"R{i}", severity=s, message="msg", file="a.py", line=i)
            for i, s in enumerate(self._severities)], files_examined=1)


def run(root, adapters, **kw):
    report = assess(root, Options(adapters=adapters, **kw))
    return report, {c["id"]: c for c in report["checks"]}


def test_all_five_statuses_are_distinguished(tree):
    root = tree({"a.py": "x = 1\n"})
    report, checks = run(root, [
        Fake("t.pass"),
        Fake("t.warn", [Severity.LOW]),
        Fake("t.fail", [Severity.HIGH, Severity.LOW]),
        Fake("t.na", languages=("cpp",)),
        Fake("t.missing-tool", tool="definitely-not-installed-eaf-tool"),
        Fake("t.network", network=True),
        Fake("t.tool-error", error=ScanNotExecuted("tool crashed")),
        Fake("t.adapter-bug", error=RuntimeError("boom")),
        Fake("t.deeper", min_depth=2),
    ])
    assert checks["t.pass"]["status"] == "PASS"
    assert checks["t.warn"]["status"] == "WARNING"
    assert checks["t.fail"]["status"] == "FAIL"
    assert checks["t.na"]["status"] == "NOT_APPLICABLE"
    for cid in ("t.missing-tool", "t.network", "t.tool-error", "t.adapter-bug", "t.deeper"):
        assert checks[cid]["status"] == "NOT_EXECUTED", cid
        assert checks[cid]["reason"], "NOT_EXECUTED must always state why"
    assert "not installed" in checks["t.missing-tool"]["reason"]
    assert "--allow-network" in checks["t.network"]["reason"]
    assert report["summary"]["overall_status"] == "FAIL"
    assert report["summary"]["check_status_counts"] == {
        "PASS": 1, "FAIL": 1, "WARNING": 1, "NOT_APPLICABLE": 1, "NOT_EXECUTED": 5}


def test_network_checks_run_only_when_allowed(tree):
    root = tree({"a.py": "x = 1\n"})
    _, checks = run(root, [Fake("t.network", network=True)], allow_network=True)
    assert checks["t.network"]["status"] == "PASS"


def test_only_and_skip_selection(tree):
    root = tree({"a.py": "x = 1\n"})
    _, checks = run(root, [Fake("a.one"), Fake("b.two")], only=["a.*"])
    assert (checks["a.one"]["status"], checks["b.two"]["status"]) == ("PASS", "NOT_EXECUTED")
    _, checks = run(root, [Fake("a.one"), Fake("b.two")], skip=["a.one"])
    assert (checks["a.one"]["status"], checks["b.two"]["status"]) == ("NOT_EXECUTED", "PASS")


def test_suppression_requires_profile_and_is_reported(tree):
    root = tree({
        "a.py": "x = 1\n",
        "eaf-profile.toml": '[[suppressions]]\ncheck="t.fail"\nrule="R0"\nreason="accepted risk #1"\n',
    })
    report, checks = run(root, [Fake("t.fail", [Severity.HIGH])])
    c = checks["t.fail"]
    assert c["status"] == "PASS" and c["suppressed_count"] == 1
    assert c["findings"][0]["suppressed"] and c["findings"][0]["suppression_reason"] == "accepted risk #1"
    assert report["summary"]["suppressed_findings"] == 1


def test_duplicate_findings_are_collapsed(tree):
    root = tree({"a.py": "x = 1\n"})

    class Dup(Fake):
        def scan(self, ctx):
            f = dict(check_id=self.id, rule_id="R", severity=Severity.LOW, message="m", file="a.py", line=1)
            return ScanOutput(findings=[Finding(**f), Finding(**f)])

    _, checks = run(root, [Dup("t.dup")])
    assert len(checks["t.dup"]["findings"]) == 1


def test_results_are_reproducible_and_scope_is_recorded(tree):
    root = tree({"a.py": "x = 1\n", "b.c": "int x;\n"})
    adapters = lambda: [Fake("t.warn", [Severity.LOW, Severity.MEDIUM]), Fake("t.pass")]  # noqa: E731
    r1, _ = run(root, adapters())
    r2, _ = run(root, adapters())
    assert r1["summary"]["results_digest"] == r2["summary"]["results_digest"]
    scope = r1["assessment"]["scope"]
    assert scope["source_digest"] == r2["assessment"]["scope"]["source_digest"]
    assert scope["source_tree_unmodified"] is True
    assert scope["files_in_scope"] == 2
    assert r1["assessment"]["policy"]["id"] == "eaf-baseline"
    assert "certification" in r1["disclaimer"]

    (root / "a.py").write_text("x = 2\n")
    r3, _ = run(root, adapters())
    assert r3["assessment"]["scope"]["source_digest"] != scope["source_digest"]


def test_unsupported_language_is_called_out(tree):
    root = tree({"Main.java": "class Main {}\n"})
    report, _ = run(root, [Fake("t.py", languages=("python",))])
    assert report["inventory"]["unsupported_languages"] == ["java"]
    assert any("java" in text for text in report["limitations"])
    assert report["summary"]["overall_status"] == "NOT_APPLICABLE"


@pytest.mark.parametrize("kwargs", [{"depth": 2}, {"depth": 9}, {"scope": "multi-repository"},
                                    {"scope": "function"}])
def test_unimplemented_depths_and_scopes_are_rejected(tree, kwargs):
    with pytest.raises(AssessmentError):
        assess(tree({"a.py": ""}), Options(adapters=[], **kwargs))


def test_missing_path_is_rejected(tmp_path):
    with pytest.raises(AssessmentError):
        assess(tmp_path / "nope", Options(adapters=[]))
