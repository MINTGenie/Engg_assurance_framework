import tomllib

import pytest

from eaf.models import CheckResult, Finding, Severity, Status
from eaf.policy import PolicyError, bundled_policies, load_policy
from eaf.profile import PROFILE_TEMPLATE, ProfileError, load_profile


def finding(sev, check="quality.ruff", suppressed=False):
    return Finding(check_id=check, rule_id="R1", severity=sev, message="m", file="a.py", line=1,
                   suppressed=suppressed)


def result(check_id, status):
    return CheckResult(id=check_id, title=check_id, category="x", status=status, scanner="t")


def test_bundled_policies_load_and_are_versioned():
    assert {"eaf-baseline", "sweap-placeholder"} <= set(bundled_policies())
    desc = load_policy("eaf-baseline").describe()
    assert desc["version"] == "1.1.0" and len(desc["sha256"]) == 64
    assert load_policy("sweap-placeholder").describe()["status"] == "placeholder"


def test_threshold_evaluation():
    p = load_policy("eaf-baseline")
    assert p.evaluate("quality.ruff", [], "standard")[0] is Status.PASS
    assert p.evaluate("quality.ruff", [finding(Severity.INFO)], "standard")[0] is Status.PASS
    assert p.evaluate("quality.ruff", [finding(Severity.LOW)], "standard")[0] is Status.WARNING
    assert p.evaluate("quality.ruff", [finding(Severity.HIGH)], "standard")[0] is Status.FAIL
    # suppressed findings do not count
    assert p.evaluate("quality.ruff", [finding(Severity.HIGH, suppressed=True)],
                      "standard")[0] is Status.PASS


def test_criticality_changes_strictness():
    p = load_policy("eaf-baseline")
    medium = [finding(Severity.MEDIUM)]
    assert p.evaluate("quality.ruff", medium, "prototype")[0] is Status.WARNING
    assert p.evaluate("quality.ruff", medium, "standard")[0] is Status.WARNING
    assert p.evaluate("quality.ruff", medium, "elevated")[0] is Status.FAIL
    # "never" thresholds: hygiene.readme can warn but not fail
    assert p.evaluate("hygiene.readme", [finding(Severity.CRITICAL)], "standard")[0] is Status.WARNING


def test_overall_aggregation():
    p = load_policy("eaf-baseline")
    assert p.overall([result("a", Status.PASS), result("b", Status.FAIL)])[0] is Status.FAIL
    assert p.overall([result("a", Status.PASS), result("b", Status.WARNING)])[0] is Status.WARNING
    assert p.overall([result("a", Status.PASS), result("b", Status.NOT_APPLICABLE)])[0] is Status.PASS
    # an unexecuted applicable check must not yield a clean PASS
    assert p.overall([result("a", Status.PASS), result("b", Status.NOT_EXECUTED)])[0] is Status.WARNING
    assert p.overall([result("a", Status.NOT_EXECUTED)])[0] is Status.NOT_EXECUTED
    assert p.overall([result("a", Status.NOT_APPLICABLE)])[0] is Status.NOT_APPLICABLE


def test_controls_take_worst_mapped_status_and_flag_unmapped():
    p = load_policy("sweap-placeholder")
    controls = {c["id"]: c for c in p.controls([result("quality.ruff", Status.PASS),
                                                 result("security.bandit", Status.FAIL),
                                                 result("secrets.detect-secrets", Status.PASS)])}
    assert controls["SWEAP-PLACEHOLDER-A"]["status"] == "FAIL"
    assert controls["SWEAP-PLACEHOLDER-B"]["status"] == "PASS"
    assert controls["SWEAP-PLACEHOLDER-C"]["status"] == "NOT_EXECUTED"


def test_custom_policy_file_and_validation(tmp_path):
    good = tmp_path / "p.toml"
    good.write_text('[policy]\nid="x"\nversion="2.1.0"\n[defaults]\nfail_at="low"\n')
    p = load_policy(str(good))
    assert p.evaluate("any", [finding(Severity.LOW)], "standard")[0] is Status.FAIL
    bad = tmp_path / "bad.toml"
    bad.write_text('[policy]\nid="x"\nversion="1"\n[checks."a"]\nfail_at="catastrophic"\n')
    with pytest.raises(PolicyError):
        load_policy(str(bad))
    with pytest.raises(PolicyError):
        load_policy("does-not-exist")


def test_profile_loading_and_validation(tmp_path):
    f = tmp_path / "eaf-profile.toml"
    f.write_text('[project]\nname="n"\n[context]\ncriticality="elevated"\n'
                 'development_mode="ai-assisted"\nai_tools=["GitHub Copilot"]\n'
                 '[assessment]\nexclude=["gen/*"]\n'
                 '[[suppressions]]\ncheck="security.bandit"\nrule="B404"\nreason="reviewed"\n')
    p = load_profile(None, tmp_path)  # auto-discovery
    assert (p.name, p.criticality, p.exclude) == ("n", "elevated", ["gen/*"])
    assert p.suppressions[0].matches("security.bandit", "B404", "x.py")
    assert not p.suppressions[0].matches("security.bandit", "B602", "x.py")

    f.write_text('[context]\ncriticality="asil-d"\n')
    with pytest.raises(ProfileError):
        load_profile(f)
    f.write_text('[[suppressions]]\ncheck="security.bandit"\n')  # no reason given
    with pytest.raises(ProfileError):
        load_profile(f)


def test_defaults_and_template():
    assert load_profile(None).criticality == "standard"
    assert tomllib.loads(PROFILE_TEMPLATE)["assessment"]["allow_network"] is False
