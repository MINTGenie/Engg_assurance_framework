import json
import shutil
import subprocess

from conftest import SAMPLES

from eaf.cli import main
from eaf.gitinfo import git_info
from eaf.report.html_report import render_html


def test_assess_writes_json_and_html_and_sets_exit_code(tmp_path, capsys):
    out = tmp_path / "reports"
    code = main(["assess", str(SAMPLES / "vuln-python-service"), "--depth", "1", "-o", str(out)])
    stdout = capsys.readouterr().out
    assert code == 1 and "OVERALL: FAIL" in stdout
    report = json.loads((out / "eaf-report.json").read_text())
    assert report["schema_version"] == "1.1"
    assert report["summary"]["overall_status"] == "FAIL"
    assert report["assessment"]["depth"] == 1
    assert "python" in report["inventory"]["languages"]
    for c in report["checks"]:
        assert c["status"] in {"PASS", "FAIL", "WARNING", "NOT_APPLICABLE", "NOT_EXECUTED"}
        if c["status"] in ("NOT_APPLICABLE", "NOT_EXECUTED"):
            assert c["reason"]
    html = (out / "eaf-report.html").read_text()
    assert "NOT APPLICABLE" in html and "NOT EXECUTED" in html
    assert "NOT a security certification" in html
    assert "<script" not in html and "http://" not in html and "https://" not in html
    assert (out / "evidence").is_dir()
    md = (out / "eaf-evidence.md").read_text()
    assert "Overall: FAIL" in md and "NOT a security certification" in md
    assert "OWASP Top 10 (2021)" in md and "Engineering practices" in md


def test_fail_on_and_formats(tmp_path):
    sample = str(SAMPLES / "vuln-python-service")
    out = tmp_path / "r"
    assert main(["assess", sample, "-o", str(out), "--fail-on", "never", "--format", "json",
                 "--no-evidence", "-q"]) == 0
    assert (out / "eaf-report.json").exists() and not (out / "eaf-report.html").exists()
    assert not (out / "evidence").exists()
    assert main(["assess", sample, "-o", str(out), "--format", "pdf", "-q"]) == 2


def test_unimplemented_depth_is_a_usage_error(tmp_path, capsys):
    assert main(["assess", str(SAMPLES / "clean-python-lib"), "--depth", "2",
                 "-o", str(tmp_path)]) == 2
    assert "not implemented" in capsys.readouterr().err


def test_scanners_and_policies_commands(capsys):
    assert main(["scanners"]) == 0 and main(["policies"]) == 0
    out = capsys.readouterr().out
    assert "quality.ruff" in out and "eaf-baseline@1.1.0" in out


def test_init_profile(tmp_path):
    target = tmp_path / "eaf-profile.toml"
    assert main(["init-profile", str(target)]) == 0
    assert main(["init-profile", str(target)]) == 2  # never overwrites


def test_html_escapes_untrusted_content(tmp_path):
    out = tmp_path / "r"
    main(["assess", str(SAMPLES / "clean-python-lib"), "-o", str(out), "-q", "--only", "hygiene.*"])
    report = json.loads((out / "eaf-report.json").read_text())
    report["checks"][0]["findings"].append({
        "check_id": "x", "rule_id": "<img src=x onerror=alert(1)>", "severity": "high",
        "message": "<script>alert(1)</script>", "file": "<b>.py", "line": 1, "cwe": None,
        "confidence": None, "suppressed": False, "suppression_reason": None, "fingerprint": "f"})
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_git_revision_is_recorded(tmp_path):
    assert git_info(tmp_path)["is_git_repository"] is False
    if not shutil.which("git"):
        return
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n")
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("-c", "user.email=t@example.invalid", "-c", "user.name=t", "add", ".")
    run("-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false",
        "commit", "-q", "-m", "init")
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                          text=True).stdout.strip()
    info = git_info(repo)
    assert info["revision"] == head and info["dirty"] is False
    (repo / "a.py").write_text("x = 2\n")
    assert git_info(repo)["dirty"] is True
    assert git_info(repo / "nonexistent-subdir".replace("nonexistent-subdir", "."))["revision"] == head
