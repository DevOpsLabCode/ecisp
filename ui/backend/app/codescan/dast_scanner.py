"""OWASP ZAP DAST scan against a user-provided, already-running,
authorized application URL -- a deliberate opt-in follow-up action after a
source scan, not something that runs automatically (unlike the SAST/SCA/
Secrets/IaC scanners, there's no repo to detect a target URL from).

Verified against a real ZAP 2.17.0 install run via its Automation
Framework (`zap.sh -cmd -autorun plan.yaml`) against this project's own
live dev stack: spider -> passiveScan-wait -> activeScan ->
passiveScan-wait -> report. The `sarif-json` report template produces
genuine SARIF 2.1.0 (confirmed: top-level `version`, a real
`tool.driver.rules` catalog with `defaultConfiguration.level`), so this
reuses `orgscan.normalize.parse_sarif` rather than a bespoke parser --
findings just carry a request URL in `file` instead of a source path,
which is the correct thing to show for a DAST finding.

The plan YAML is generated per scan (the target URL is user input, not
known ahead of time) and written to a throwaway temp file; each run also
gets its own isolated ZAP home directory (`-dir`) so scans never share
state.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 -- fixed `zap.sh -cmd -autorun <plan>` invocation, no shell, no user input in argv
import tempfile
from pathlib import Path

from ..orgscan.models import Finding
from ..orgscan.normalize import parse_sarif

DEFAULT_SPIDER_MINUTES = 2
DEFAULT_ACTIVE_SCAN_MINUTES = 5


class DastUnavailable(Exception):
    """The `zap.sh` binary isn't installed in this environment."""


class DastExecutionError(Exception):
    """ZAP ran but the automation plan failed or produced no report."""


def _zap_binary() -> str:
    path = shutil.which("zap.sh")
    if not path:
        raise DastUnavailable("'zap.sh' is not installed")
    return path


def _plan_yaml(target_url: str, report_path: Path, spider_minutes: int, active_scan_minutes: int) -> str:
    return f"""\
env:
  contexts:
    - name: target
      urls:
        - {target_url}
  parameters:
    failOnError: false
    progressToStdout: true
jobs:
  - type: spider
    parameters:
      context: target
      url: {target_url}
      maxDuration: {spider_minutes}
  - type: passiveScan-wait
    parameters:
      maxDuration: {spider_minutes}
  - type: activeScan
    parameters:
      context: target
      maxRuleDurationInMins: {max(1, active_scan_minutes // 5)}
      maxScanDurationInMins: {active_scan_minutes}
  - type: passiveScan-wait
    parameters:
      maxDuration: {spider_minutes}
  - type: report
    parameters:
      template: sarif-json
      reportDir: {report_path.parent}
      reportFile: {report_path.stem}
      reportTitle: Golem DAST scan
"""


def run_dast(
    target_url: str,
    spider_minutes: int = DEFAULT_SPIDER_MINUTES,
    active_scan_minutes: int = DEFAULT_ACTIVE_SCAN_MINUTES,
) -> list[Finding]:
    zap_bin = _zap_binary()

    with tempfile.TemporaryDirectory(prefix="dast-") as work_dir:
        work = Path(work_dir)
        report_path = work / "zap-report.json"
        plan_path = work / "plan.yaml"
        plan_path.write_text(_plan_yaml(target_url, report_path, spider_minutes, active_scan_minutes))
        zap_home = work / "zap-home"

        # No timeout param on this one: the plan's own maxDuration/
        # maxScanDurationInMins caps are what actually bound run time, and
        # they're already generous multiples of the user-provided minutes.
        proc = subprocess.run(  # nosec B603
            [zap_bin, "-cmd", "-autorun", str(plan_path), "-dir", str(zap_home)],
            capture_output=True,
            text=True,
            check=False,
        )
        if "Automation plan succeeded!" not in proc.stdout:
            raise DastExecutionError(f"ZAP automation plan did not succeed: {proc.stdout[-1500:]}")

        if not report_path.exists() or report_path.stat().st_size == 0:
            raise DastExecutionError("ZAP did not produce a report")
        sarif_text = report_path.read_text()

    return parse_sarif(
        sarif_text,
        repository=target_url,
        scanner="zap",
        category="dast",
        remediation_hint="See the ZAP rule's `solution` text (zaproxy.org) for the specific fix.",
    )
