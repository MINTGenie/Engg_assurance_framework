"""Configurable guidance packs, practice checks and standards coverage."""
import pytest
from conftest import SAMPLES

from eaf.engine import Options, assess
from eaf.guidance import GuidanceError, load_guidance
from eaf.models import Finding, Severity

SPEC = "# Feature: login\n\n" + "The system shall authenticate users. " * 40 + \
       "\n\n## Acceptance criteria\n\n- REQ-001 Given a valid token when ... then ...\n"
README = "# Tool\n\n## Overview\nx\n## Installation\nx\n## Usage\nx\n## Testing\nx\n"


def practices(root, **kw):
    report = assess(root, Options(only=["practice.*"], **kw))
    return report, {c["id"]: c for c in report["checks"] if c["category"] == "practices"}


def test_bundled_pack_is_versioned_and_complete():
    pack = load_guidance("eaf-practices")
    d = pack.describe()
    assert d["version"] == "1.0.0" and len(d["sha256"]) == 64
    ids = {p["id"] for p in pack.practices}
    assert {"spec.present", "spec.acceptance-criteria", "docs.architecture", "docs.readme-sections",
            "docs.api-contract", "ai.agent-instructions", "docs.freshness"} <= ids
    for p in pack.practices:
        assert p.get("why") and p.get("how"), f"{p['id']} has no guidance text"


def test_bare_repository_gets_guidance_not_failure(tree):
    report, checks = practices(tree({"main.py": "print(1)\n"}))
    spec = checks["practice.spec.present"]
    assert spec["status"] == "WARNING"                      # guides, does not block
    f = spec["findings"][0]
    assert f["rule_id"] == "not-found" and "spec" in f["guidance"].lower()
    assert checks["practice.docs.readme-sections"]["findings"][0]["rule_id"] == "no-readme"
    assert checks["practice.docs.api-contract"]["status"] == "NOT_APPLICABLE"   # no API detected
    assert checks["practice.ai.agent-instructions"]["status"] == "WARNING"
    assert report["assessment"]["guidance"]["id"] == "eaf-practices"


def test_spec_driven_repository_is_recognised(tree):
    root = tree({
        "main.py": "print(1)\n", "specs/login.md": SPEC, "README.md": README,
        "docs/architecture.md": "# Architecture\n" + "component " * 120,
        "CHANGELOG.md": "## 1.0.0\n- first\n", "CONTRIBUTING.md": "review rules\n",
        "SECURITY.md": "report to security@example.invalid\n",
        "AGENTS.md": "Read the spec in specs/ first. " * 30,
    })
    _, checks = practices(root)
    for cid in ("practice.spec.present", "practice.spec.acceptance-criteria",
                "practice.docs.readme-sections", "practice.docs.architecture",
                "practice.docs.changelog", "practice.docs.contribution-process",
                "practice.docs.security-policy", "practice.ai.agent-instructions"):
        assert checks[cid]["status"] == "PASS", (cid, checks[cid]["findings"])
    assert any("specs/login.md" in n for n in checks["practice.spec.present"]["notes"])


def test_thin_or_untestable_spec_is_called_out(tree):
    root = tree({"main.py": "x = 1\n", "specs/login.md": "# Login\nUsers can log in.\n"})
    _, checks = practices(root)
    assert checks["practice.spec.present"]["findings"][0]["rule_id"] == "too-thin"
    assert checks["practice.spec.acceptance-criteria"]["findings"][0]["rule_id"] == "content-missing"


def test_conditions_follow_profile_and_technology(tree):
    root = tree({"main.py": "x = 1\n", "requirements.txt": "fastapi==0.115.0\n",
                 "eaf-profile.toml": '[context]\ndevelopment_mode = "conventional"\n'})
    _, checks = practices(root)
    assert checks["practice.ai.agent-instructions"]["status"] == "NOT_APPLICABLE"
    assert checks["practice.docs.api-contract"]["status"] == "WARNING"     # FastAPI, no OpenAPI doc
    assert checks["practice.docs.mcp-tools"]["status"] == "NOT_APPLICABLE"


def test_elevated_criticality_makes_a_missing_spec_fail(tree):
    root = tree({"main.py": "x = 1\n", "eaf-profile.toml": '[context]\ncriticality = "elevated"\n'})
    _, checks = practices(root)
    assert checks["practice.spec.present"]["status"] == "FAIL"


def test_custom_pack_extends_overrides_disables_and_adds(tree, tmp_path):
    pack = tmp_path / "team.toml"
    pack.write_text('''
[guidance]
id = "team-x"
version = "2.0.0"
extends = "eaf-practices"
disable = ["docs.changelog", "ai.*"]

[[practice]]
id = "spec.present"
title = "Requirements live in Doors export"
severity = "high"
paths = ["doors/*.csv"]
why = "Team rule."
how = "Export the module to doors/."

[[practice]]
id = "team.runbook"
title = "Operations runbook"
paths = ["docs/runbook.md"]
how = "Write docs/runbook.md."

[[remediation]]
check = "security.bandit"
rule = "B602"
guidance = "TEAM RULE: use the internal process wrapper."
''')
    loaded = load_guidance(str(pack))
    assert loaded.describe()["extends"] == ["eaf-practices@1.0.0"]
    ids = [p["id"] for p in loaded.practices]
    assert "docs.changelog" not in ids and "ai.agent-instructions" not in ids
    assert ids.count("spec.present") == 1 and "team.runbook" in ids

    root = tree({"main.py": "x = 1\n", "docs/runbook.md": "steps\n"})
    report, checks = practices(root, guidance=str(pack))
    assert report["assessment"]["guidance"]["id"] == "team-x"
    f = checks["practice.spec.present"]["findings"][0]
    assert f["severity"] == "high" and "doors/" in f["guidance"]
    assert checks["practice.team.runbook"]["status"] == "PASS"
    assert "practice.docs.changelog" not in checks

    # remediation text for scanner findings is configurable too; own entries win
    finding = Finding(check_id="security.bandit", rule_id="B602", severity=Severity.HIGH, message="m",
                      cwe="CWE-78", guidance="tool default")
    loaded.enrich(finding)
    assert finding.guidance.startswith("TEAM RULE")
    assert {"CWE-78", "OWASP-2021-A03"} <= set(finding.standards)


def test_profile_can_select_pack_and_skip_practices(tree, tmp_path):
    root = tree({"main.py": "x = 1\n", "eaf-profile.toml":
                 '[assessment]\nskip_checks = ["practice.docs.*"]\n'})
    _, checks = practices(root)
    assert checks["practice.docs.changelog"]["status"] == "NOT_EXECUTED"
    assert checks["practice.spec.present"]["status"] == "WARNING"


@pytest.mark.parametrize("body", [
    '[guidance]\nid = "x"\n',                                                       # no version
    '[guidance]\nid="x"\nversion="1"\n[[practice]]\nid="a"\n',                      # nothing to check
    '[guidance]\nid="x"\nversion="1"\n[[practice]]\nid="a"\npaths=["x"]\nseverity="huge"\n',
    '[guidance]\nid="x"\nversion="1"\n[[practice]]\nid="a"\npaths=["x"]\napplies_when=["moon"]\n',
])
def test_invalid_packs_are_rejected(tmp_path, body):
    f = tmp_path / "bad.toml"
    f.write_text(body)
    with pytest.raises(GuidanceError):
        load_guidance(str(f))
    with pytest.raises(GuidanceError):
        load_guidance("no-such-pack")


def test_standards_coverage_is_never_reported_as_full():
    report = assess(SAMPLES / "api-mcp-vector-service", Options(skip=["dependencies.*"]))
    stds = {s["id"]: {c["id"]: c for c in s["categories"]} for s in report["standards_coverage"]}
    assert set(stds) == {"OWASP-2021", "OWASP-API-2023"}
    assert all(len(v) == 10 for v in stds.values())
    for cats in stds.values():
        for c in cats.values():
            assert c["coverage"] in ("partial", "none") and c["not_covered"]
    a03 = stds["OWASP-2021"]["OWASP-2021-A03"]
    assert a03["coverage"] == "partial" and a03["status"] == "FAIL" and a03["findings_tagged"] > 0
    assert stds["OWASP-2021"]["OWASP-2021-A09"]["coverage"] == "none"
    assert stds["OWASP-API-2023"]["OWASP-API-2023-API2"]["status"] == "FAIL"
    assert any("partial by construction" in x for x in report["limitations"])


def test_doc_freshness_needs_real_history(tree):
    import shutil
    import subprocess
    if not shutil.which("git"):
        pytest.skip("git not installed")
    root = tree({"main.py": "x = 1\n", "README.md": README})
    git = ["git", "-C", str(root), "-c", "user.email=t@example.invalid", "-c", "user.name=t",
           "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run([*git, "add", "README.md"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "docs", "--date", "2025-01-01T00:00:00"], check=True,
                   env={"GIT_COMMITTER_DATE": "2025-01-01T00:00:00", "PATH": __import__("os").environ["PATH"]})
    subprocess.run([*git, "add", "main.py"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "code"], check=True,
                   env={"GIT_COMMITTER_DATE": "2026-06-01T00:00:00", "PATH": __import__("os").environ["PATH"]})
    _, checks = practices(root)
    fresh = checks["practice.docs.freshness"]
    assert fresh["status"] == "WARNING" and fresh["findings"][0]["rule_id"] == "stale-docs"

    # a shallow clone cannot answer the question and must say so instead of passing
    clone = root.parent / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{root}", str(clone)], check=True)
    _, checks = practices(clone)
    assert checks["practice.docs.freshness"]["status"] == "NOT_EXECUTED"
