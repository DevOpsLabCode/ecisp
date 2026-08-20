from dataclasses import dataclass

import pytest

from app.orgscan.models import Finding
from app.registryscan.registry_scan_job import manager as registry_scan_manager
from app.runtimedefender.sca_correlation import correlate_image_with_registry_scans


@dataclass
class _FakeResult:
    findings: list[Finding]

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] += 1
        return counts


class _FakeScan:
    def __init__(self, scan_id, image_ref, status, findings):
        self.id = scan_id
        self.image_ref = image_ref
        self.status = status
        self.finished_at = "2026-08-15T00:00:00Z"
        self.result = _FakeResult(findings) if findings is not None else None


def _finding(severity="critical"):
    return Finding(
        repository="alpine:3.18",
        file="alpine:3.18",
        scanner="trivy",
        rule_id="CVE-2024-0001",
        severity=severity,
        category="sca",
        message="a vulnerability",
    )


@pytest.fixture(autouse=True)
def isolated_registry_scans(monkeypatch):
    scans: list[_FakeScan] = []
    monkeypatch.setattr(registry_scan_manager, "list", lambda: scans)
    return scans


def test_returns_none_for_no_image_ref():
    assert correlate_image_with_registry_scans(None) is None


def test_returns_none_when_no_scan_matches(isolated_registry_scans):
    isolated_registry_scans.append(_FakeScan("scan-1", "other:image", "completed", [_finding()]))
    assert correlate_image_with_registry_scans("alpine:3.18") is None


def test_returns_none_when_matching_scan_is_not_completed(isolated_registry_scans):
    isolated_registry_scans.append(_FakeScan("scan-1", "alpine:3.18", "running", None))
    assert correlate_image_with_registry_scans("alpine:3.18") is None


def test_returns_none_when_matching_scan_has_no_findings(isolated_registry_scans):
    isolated_registry_scans.append(_FakeScan("scan-1", "alpine:3.18", "completed", []))
    assert correlate_image_with_registry_scans("alpine:3.18") is None


def test_returns_a_correlation_note_for_a_matching_scan_with_findings(isolated_registry_scans):
    isolated_registry_scans.append(
        _FakeScan("scan-1", "alpine:3.18", "completed", [_finding("critical"), _finding("high")])
    )
    note = correlate_image_with_registry_scans("alpine:3.18")
    assert note is not None
    assert "alpine:3.18" in note
    assert "scan-1" in note
    assert "2 known vulnerabilities" in note
    assert "1 critical" in note
    assert "1 high" in note


def test_uses_the_most_recent_matching_scan(isolated_registry_scans):
    # manager.list() returns newest-first (see registry_scan_job.py), so the
    # most recently registered fake scan goes at index 0 here too.
    isolated_registry_scans.append(
        _FakeScan("scan-new", "alpine:3.18", "completed", [_finding(), _finding()])
    )
    isolated_registry_scans.append(_FakeScan("scan-old", "alpine:3.18", "completed", [_finding()]))
    note = correlate_image_with_registry_scans("alpine:3.18")
    assert "scan-new" in note
    assert "2 known vulnerabilities" in note
