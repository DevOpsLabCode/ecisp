"""SpotBugs -- Java bytecode analysis. Unlike the other scanners, SpotBugs
analyzes *compiled* `.class` files, not source, so this adapter has to
build the project first:

  1. Compile: `mvn -q -B compile` (Maven) or the Gradle wrapper's
     `compileJava` task, whichever build file is present.
  2. Run the standalone `spotbugs` CLI against the resulting classes
     directory (`target/classes` for Maven, `build/classes/java/main` for
     Gradle) with `-xml:withMessages`.
  3. Parse the XML `BugInstance` elements.

A repo that can't build offline (missing a dependency, no network access
to Maven Central) is a real, expected failure mode here -- `base.py`'s
`ScannerExecutionError` surfaces it as a per-scanner skip with the build
output as the reason, rather than failing the whole repo scan.

Verified against a real JDK 21 + Maven 3.9.9 + spotbugs 4.8.6 install
(Docker image build) against a Maven fixture project with a JDBC
SQL-injection-adjacent pattern -- see the `run()` function below for the
`-xml:withMessages` discovery that came out of that run.

Uses defusedxml rather than the stdlib xml.etree.ElementTree: SpotBugs'
output is this codebase's own tool invocation, not attacker-controlled
input, but a security scanner parsing XML with a parser that's vulnerable
to XXE/billion-laughs by default is exactly the kind of thing it would
itself flag in someone else's code.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import defusedxml.ElementTree as ET

from ..models import Finding
from ..severity import spotbugs as spotbugs_severity
from .base import ScannerExecutionError, require, run_capture

SCANNER_ID = "spotbugs"


def _compile(repo_dir: Path) -> Path:
    if (repo_dir / "pom.xml").exists():
        require("mvn")
        run_capture(["mvn", "-q", "-B", "compile"], cwd=repo_dir, timeout=1200)
        classes_dir = repo_dir / "target" / "classes"
    else:
        gradlew = repo_dir / "gradlew"
        binary = str(gradlew) if gradlew.exists() else require("gradle")
        if gradlew.exists():
            gradlew.chmod(0o755)
        run_capture([binary, "compileJava", "--no-daemon"], cwd=repo_dir, timeout=1200)
        classes_dir = repo_dir / "build" / "classes" / "java" / "main"

    if not classes_dir.exists() or not any(classes_dir.rglob("*.class")):
        raise ScannerExecutionError(f"build produced no compiled classes in {classes_dir}")
    return classes_dir


def run(repo_dir: Path, repository: str) -> list[Finding]:
    require("spotbugs")
    classes_dir = _compile(repo_dir)

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        out_path = tmp.name
    try:
        run_capture(
            ["spotbugs", "-textui", "-xml:withMessages", "-output", out_path, str(classes_dir)],
            cwd=repo_dir,
            ok_exit_codes=(0, 1),
            timeout=900,
        )
        xml_text = Path(out_path).read_text()
    finally:
        Path(out_path).unlink(missing_ok=True)

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScannerExecutionError(f"spotbugs produced invalid XML: {exc}") from exc

    findings: list[Finding] = []
    for bug in root.findall("BugInstance"):
        source_line = bug.find("SourceLine")
        bug_type = bug.get("type", "SpotBugs finding")
        # Verified against a real spotbugs 4.8.6 run: `-xml:withMessages`
        # does not actually embed a <LongMessage> per BugInstance the way
        # its name implies (no message catalog appears anywhere in the
        # output either) -- the bug pattern's `type` code is the only
        # description this CLI reliably provides, so that's what's used
        # here. It's still directly actionable: SpotBugs bug pattern codes
        # are documented at spotbugs.readthedocs.io (see remediation below).
        category = bug.get("category")
        long_message = f"{category}: {bug_type}" if category else bug_type
        file_path = source_line.get("sourcepath") if source_line is not None else "unknown"
        line = None
        if source_line is not None and source_line.get("start"):
            line = int(source_line.get("start"))

        try:
            priority = int(bug.get("priority", "2"))
        except ValueError:
            priority = 2

        findings.append(
            Finding(
                repository=repository,
                file=file_path or "unknown",
                line=line,
                scanner=SCANNER_ID,
                rule_id=bug.get("type", "UNKNOWN"),
                severity=spotbugs_severity(priority),
                category="sast",
                message=long_message,
                remediation="See the SpotBugs bug pattern description (spotbugs.readthedocs.io) for the fix.",
            )
        )
    return findings
