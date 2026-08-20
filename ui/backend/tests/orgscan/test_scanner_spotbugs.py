"""Verified against a real JVM 21 + Maven 3.9.9 + spotbugs 4.8.6 install
(Docker image build) -- see scanners/spotbugs.py's docstring, including the
discovery that `-xml:withMessages` doesn't actually embed a per-instance
description the way its name implies; this fixture is the real shape that
invocation produces (no `<LongMessage>` anywhere in the document).
"""

from pathlib import Path

import pytest

from app.orgscan.scanners import spotbugs
from app.orgscan.scanners.base import ScannerExecutionError

_REAL_SPOTBUGS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<BugCollection>
  <BugInstance type="SQL_INJECTION_JDBC" priority="1" category="SECURITY">
    <SourceLine sourcepath="com/example/Foo.java" start="42" end="42"/>
  </BugInstance>
</BugCollection>
"""


def _maven_project_with_compiled_classes(tmp_path: Path) -> Path:
    (tmp_path / "pom.xml").write_text("<project></project>")
    classes_dir = tmp_path / "target" / "classes"
    classes_dir.mkdir(parents=True)
    (classes_dir / "Foo.class").write_bytes(b"\xca\xfe\xba\xbe")
    return tmp_path


def test_spotbugs_compiles_via_maven_and_parses_xml(tmp_path, monkeypatch):
    repo_dir = _maven_project_with_compiled_classes(tmp_path)

    def fake_run_capture(args, cwd, ok_exit_codes=(0,), timeout=600):
        if args[0] == "mvn":
            return ""  # compile step -- classes dir already pre-populated above
        out_path = args[args.index("-output") + 1]
        Path(out_path).write_text(_REAL_SPOTBUGS_XML)
        return ""

    monkeypatch.setattr(spotbugs, "require", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(spotbugs, "run_capture", fake_run_capture)

    findings = spotbugs.run(repo_dir, "org/repo")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SQL_INJECTION_JDBC"
    assert f.file == "com/example/Foo.java"
    assert f.line == 42
    assert f.severity == "high"  # priority 1 -> high
    assert f.message == "SECURITY: SQL_INJECTION_JDBC"  # category + type, since no LongMessage is available


def test_spotbugs_uses_gradle_wrapper_when_pom_absent(tmp_path, monkeypatch):
    (tmp_path / "build.gradle").write_text("plugins {}")
    gradlew = tmp_path / "gradlew"
    gradlew.write_text("#!/bin/sh\n")
    classes_dir = tmp_path / "build" / "classes" / "java" / "main"
    classes_dir.mkdir(parents=True)
    (classes_dir / "Foo.class").write_bytes(b"\xca\xfe\xba\xbe")

    calls = []

    def fake_run_capture(args, cwd, ok_exit_codes=(0,), timeout=600):
        calls.append(args[0])
        if "compileJava" in args:
            return ""
        out_path = args[args.index("-output") + 1]
        Path(out_path).write_text("<BugCollection></BugCollection>")
        return ""

    monkeypatch.setattr(spotbugs, "require", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(spotbugs, "run_capture", fake_run_capture)

    findings = spotbugs.run(tmp_path, "org/repo")
    assert findings == []
    assert str(gradlew) in calls[0]


def test_spotbugs_raises_when_build_produces_no_classes(tmp_path, monkeypatch):
    (tmp_path / "pom.xml").write_text("<project></project>")
    monkeypatch.setattr(spotbugs, "require", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(spotbugs, "run_capture", lambda *a, **k: "")

    with pytest.raises(ScannerExecutionError, match="no compiled classes"):
        spotbugs.run(tmp_path, "org/repo")


def test_spotbugs_raises_on_invalid_xml(tmp_path, monkeypatch):
    repo_dir = _maven_project_with_compiled_classes(tmp_path)

    def fake_run_capture(args, cwd, ok_exit_codes=(0,), timeout=600):
        if args[0] == "mvn":
            return ""
        out_path = args[args.index("-output") + 1]
        Path(out_path).write_text("not xml at all <<<")
        return ""

    monkeypatch.setattr(spotbugs, "require", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(spotbugs, "run_capture", fake_run_capture)

    with pytest.raises(ScannerExecutionError, match="invalid XML"):
        spotbugs.run(repo_dir, "org/repo")
