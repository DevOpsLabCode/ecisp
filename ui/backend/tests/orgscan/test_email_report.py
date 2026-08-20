import smtplib

import pytest

from app.orgscan import email_report
from app.orgscan.models import Finding, RepoScanResult


class _FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=30):
        self.host = host
        self.port = port
        self.started_tls = False
        self.login_args = None
        self.sent_message = None
        _FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        self.started_tls = True

    def login(self, username, password):
        self.login_args = (username, password)

    def send_message(self, msg):
        self.sent_message = msg


@pytest.fixture(autouse=True)
def _clear_fake_smtp_instances():
    _FakeSMTP.instances.clear()
    yield
    _FakeSMTP.instances.clear()


def _sample_result():
    findings = [
        Finding(
            repository="org/repo",
            file="a.py",
            line=3,
            scanner="bandit",
            rule_id="B105",
            severity="high",
            category="sast",
            message="m",
        )
    ]
    return RepoScanResult(
        repository="org/repo", technologies=["bandit"], scanners_run=["bandit"], scanners_skipped={}, findings=findings
    )


def test_is_configured_reflects_smtp_host_env_var(monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    assert email_report.is_configured() is False
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    assert email_report.is_configured() is True


def test_send_report_is_a_noop_without_smtp_host(monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    sent = email_report.send_report("to@example.com", "my-org", [_sample_result()], "COMPLETED", {})
    assert sent is False


def test_send_report_sends_via_smtp_with_attachments(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "user")
    monkeypatch.setenv("SMTP_PASSWORD", "pass")
    monkeypatch.setenv("SMTP_FROM", "scanner@golem.local")
    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)

    attachments = {"security-report.html": (b"<html></html>", "html"), "security-findings.json": (b"{}", "json")}
    sent = email_report.send_report("security@example.com", "my-org", [_sample_result()], "COMPLETED", attachments)

    assert sent is True
    smtp = _FakeSMTP.instances[0]
    assert smtp.started_tls is True
    assert smtp.login_args == ("user", "pass")
    msg = smtp.sent_message
    assert msg["To"] == "security@example.com"
    assert "my-org" in msg["Subject"]
    payloads = list(msg.iter_attachments())
    assert len(payloads) == 2


def test_send_report_skips_tls_and_login_when_not_configured(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USE_TLS", "false")
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)

    email_report.send_report("to@example.com", "my-org", [_sample_result()], "COMPLETED", {})

    smtp = _FakeSMTP.instances[0]
    assert smtp.started_tls is False
    assert smtp.login_args is None


def test_summary_text_includes_totals_across_repos():
    r1 = _sample_result()
    r2 = RepoScanResult(repository="org/clean", technologies=[], scanners_run=[], scanners_skipped={}, findings=[])
    text = email_report._summary_text("my-org", [r1, r2], "COMPLETED")
    assert "Repositories scanned: 2" in text
    assert "Repositories with findings: 1" in text
    assert "High: 1" in text
