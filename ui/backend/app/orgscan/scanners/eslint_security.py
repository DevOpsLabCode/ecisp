"""ESLint + eslint-plugin-security -- JS/TS SAST.

Verified against a real install: eslint-plugin-security 3.0.1's rules use
the pre-ESLint-9 `context.getSourceCode()` API and crash under ESLint 10's
runtime (`TypeError: context.getSourceCode is not a function`), so this
pins ESLint 8.x specifically -- the Dockerfile installs eslint@8.57.1
alongside the plugin into a fixed tools directory
(`ORGSCAN_ESLINT_TOOLS_DIR`, default `/opt/orgscan-node-tools`) rather than
whatever ESLint version the scanned repo itself might depend on.

`--resolve-plugins-relative-to` points plugin resolution at that same
fixed tools directory (which the Dockerfile installs eslint-plugin-security
into alongside the eslint binary) regardless of the target repo's own
node_modules, and `-c .../eslint-security.eslintrc.json --no-eslintrc`
makes sure only our security ruleset runs, not whatever lint config (or
lack of one) the target repo ships.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from ..models import Finding
from .base import ScannerUnavailable, require, run_capture

SCANNER_ID = "eslint_security"
_REMEDIATION = "See eslint-plugin-security's rule docs (github.com/eslint-community/eslint-plugin-security)"

_RULESET_DIR = Path(__file__).resolve().parent.parent / "rulesets"
_ESLINTRC = _RULESET_DIR / "eslint-security.eslintrc.json"

_SEVERITY = {2: "high", 1: "medium"}


def run(repo_dir: Path, repository: str) -> list[Finding]:
    tools_dir = Path(os.environ.get("ORGSCAN_ESLINT_TOOLS_DIR", "/opt/orgscan-node-tools"))
    eslint_bin = tools_dir / "node_modules" / ".bin" / "eslint"
    if not eslint_bin.exists():
        raise ScannerUnavailable(f"eslint tools not found at {eslint_bin}")
    require(str(eslint_bin)) if os.name != "nt" else None

    stdout = run_capture(
        [
            str(eslint_bin),
            "--no-eslintrc",
            "--resolve-plugins-relative-to",
            str(tools_dir),
            "-c",
            str(_ESLINTRC),
            "--no-ignore",
            "-f",
            "json",
            ".",
        ],
        cwd=repo_dir,
        # ESLint exits 1 when lint problems were found, 2 on a fatal
        # config/parse error -- but even a fatal error still prints a
        # (possibly empty) valid JSON array to stdout for the `json`
        # formatter, so we accept both and let json.loads below fail loudly
        # if that assumption is ever wrong.
        ok_exit_codes=(0, 1, 2),
    )

    results = json.loads(stdout)
    findings: list[Finding] = []
    for file_result in results:
        rel_path = os.path.relpath(file_result["filePath"], repo_dir)
        for msg in file_result.get("messages", []):
            rule_id = msg.get("ruleId") or "eslint-error"
            findings.append(
                Finding(
                    repository=repository,
                    file=rel_path,
                    line=msg.get("line"),
                    scanner=SCANNER_ID,
                    rule_id=rule_id,
                    severity=_SEVERITY.get(msg.get("severity"), "medium"),
                    category="sast",
                    message=msg.get("message", rule_id),
                    remediation=_REMEDIATION,
                )
            )
    return findings
