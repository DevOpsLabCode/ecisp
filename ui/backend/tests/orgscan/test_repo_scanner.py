import types

from app.orgscan import repo_scanner
from app.orgscan.models import Finding
from app.orgscan.scanners.base import ScannerExecutionError, ScannerUnavailable


def _fake_module(scanner_id, *, findings=None, raises=None):
    mod = types.SimpleNamespace()
    mod.SCANNER_ID = scanner_id

    def run(repo_dir, repository):
        if raises:
            raise raises
        return findings or []

    mod.run = run
    return mod


def test_scan_repo_runs_applicable_scanners_and_dedupes(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask\n")  # makes tech_detect pick bandit + semgrep

    # Two distinct Finding objects with the same (repo, file, rule, line) --
    # i.e. the same fingerprint -- reported independently by each scanner,
    # the way two real tools agreeing on one line would look.
    finding_from_bandit = Finding(
        repository="org/repo",
        file="a.py",
        line=1,
        scanner="bandit",
        rule_id="R1",
        severity="high",
        category="sast",
        message="m",
    )
    finding_from_semgrep = Finding(
        repository="org/repo",
        file="a.py",
        line=1,
        scanner="semgrep",
        rule_id="R1",
        severity="high",
        category="sast",
        message="m",
    )
    fake_registry = {
        "bandit": _fake_module("bandit", findings=[finding_from_bandit]),
        "semgrep": _fake_module("semgrep", findings=[finding_from_semgrep]),
    }
    monkeypatch.setattr(repo_scanner, "REGISTRY", fake_registry)

    result = repo_scanner.scan_repo(tmp_path, "org/repo")
    # tech_detect always includes "trivy" (see its own tests) regardless of
    # what the fake REGISTRY here knows how to run -- .technologies reflects
    # real detection, .scanners_run reflects what actually ran against it.
    assert set(result.technologies) == {"bandit", "semgrep", "trivy"}
    assert set(result.scanners_run) == {"bandit", "semgrep"}
    assert result.scanners_skipped == {}
    assert len(result.findings) == 1
    assert result.findings[0].scanner == "bandit+semgrep"


def test_scan_repo_records_skip_reason_for_unavailable_scanner(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask\n")
    fake_registry = {
        "bandit": _fake_module("bandit", raises=ScannerUnavailable("bandit not installed")),
        "semgrep": _fake_module("semgrep", findings=[]),
    }
    monkeypatch.setattr(repo_scanner, "REGISTRY", fake_registry)

    result = repo_scanner.scan_repo(tmp_path, "org/repo")
    assert "bandit" in result.scanners_skipped
    assert "not installed" in result.scanners_skipped["bandit"]
    assert "semgrep" in result.scanners_run


def test_scan_repo_records_skip_reason_for_execution_error(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask\n")
    fake_registry = {
        "bandit": _fake_module("bandit", raises=ScannerExecutionError("build failed")),
        "semgrep": _fake_module("semgrep", findings=[]),
    }
    monkeypatch.setattr(repo_scanner, "REGISTRY", fake_registry)

    result = repo_scanner.scan_repo(tmp_path, "org/repo")
    assert result.scanners_skipped["bandit"] == "build failed"


def test_scan_repo_catches_unexpected_exceptions_without_aborting(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask\n")
    fake_registry = {
        "bandit": _fake_module("bandit", raises=RuntimeError("boom")),
        "semgrep": _fake_module("semgrep", findings=[]),
    }
    monkeypatch.setattr(repo_scanner, "REGISTRY", fake_registry)

    result = repo_scanner.scan_repo(tmp_path, "org/repo")
    assert "unexpected error" in result.scanners_skipped["bandit"]
    assert "semgrep" in result.scanners_run


def test_scan_repo_respects_only_scanners_filter(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask\n")
    fake_registry = {"bandit": _fake_module("bandit", findings=[]), "semgrep": _fake_module("semgrep", findings=[])}
    monkeypatch.setattr(repo_scanner, "REGISTRY", fake_registry)

    result = repo_scanner.scan_repo(tmp_path, "org/repo", only_scanners={"bandit"})
    assert result.scanners_run == ["bandit"]


def test_scan_repo_records_exclude_scanners_as_a_skip_with_reason(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask\n")
    fake_registry = {"bandit": _fake_module("bandit", findings=[]), "semgrep": _fake_module("semgrep", findings=[])}
    monkeypatch.setattr(repo_scanner, "REGISTRY", fake_registry)

    result = repo_scanner.scan_repo(
        tmp_path, "org/repo", exclude_scanners={"bandit": "disabled: requires executing untrusted code"}
    )
    assert result.scanners_run == ["semgrep"]
    assert result.scanners_skipped == {"bandit": "disabled: requires executing untrusted code"}


def test_scan_repo_with_no_applicable_technologies(tmp_path, monkeypatch):
    (tmp_path / "README.md").write_text("hello\n")
    monkeypatch.setattr(repo_scanner, "REGISTRY", {"bandit": _fake_module("bandit", findings=[])})

    result = repo_scanner.scan_repo(tmp_path, "org/repo")
    assert result.technologies == ["trivy"]  # the one scanner tech_detect never gates on
    assert result.scanners_run == []
    assert result.findings == []
