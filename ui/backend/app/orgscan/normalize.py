"""Generic SARIF -> Finding conversion, shared by every scanner adapter that
emits native SARIF (checkov, semgrep, gosec, the ESLint SARIF formatter, and
the Roslyn/dotnet-build path used for Security Code Scan).

SARIF already normalizes each tool's own severity vocabulary into a
`level` of error/warning/note/none, so a single conversion here covers five
of the eight scanners instead of five bespoke JSON parsers. Bandit's SARIF
also carries its original `issue_severity` in `properties`, which we prefer
when present since it's more precise than the 4-value `level` scale.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import unquote, urlparse

from .models import Finding

_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _security_severity_score(props: dict) -> str | None:
    raw = props.get("security-severity")
    if raw is None:
        return None
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _rule_for(result: dict, rules: list[dict], rules_by_id: dict[str, dict]) -> dict:
    # SARIF producers are inconsistent about which of ruleIndex/ruleId they
    # populate on a result -- semgrep, for one, only sets ruleId. Try the
    # index first (cheaper, unambiguous) and fall back to a name lookup.
    idx = result.get("ruleIndex")
    if idx is not None and 0 <= idx < len(rules):
        return rules[idx]
    return rules_by_id.get(result.get("ruleId", ""), {})


def _location(result: dict, base_dir: Path | None) -> tuple[str, int | None]:
    locations = result.get("locations") or []
    if not locations:
        return "unknown", None

    loc = locations[0]
    # SARIF 2.1.0 uses `physicalLocation` -- but .NET's own `/p:ErrorLog=`
    # SARIF logger emits the pre-2.1 `resultFile` shape instead, even when
    # `version=2.1` is explicitly requested (verified against a real
    # `dotnet build` run; see scanners/security_code_scan.py).
    phys = loc.get("physicalLocation") or loc.get("resultFile") or {}
    uri = phys.get("artifactLocation", phys).get("uri", "unknown")
    line = phys.get("region", {}).get("startLine")

    if uri.startswith("file://"):
        path = unquote(urlparse(uri).path)
        uri = os.path.relpath(path, base_dir) if base_dir else path

    return uri, line


def _level_for(result: dict, rule: dict) -> str:
    level = result.get("level")
    if level:
        return level
    return rule.get("defaultConfiguration", {}).get("level", "warning")


def parse_sarif(
    sarif_text: str,
    repository: str,
    scanner: str,
    category: str,
    remediation_hint: str | None = None,
    base_dir: Path | None = None,
) -> list[Finding]:
    doc = json.loads(sarif_text)
    findings: list[Finding] = []
    for run in doc.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        rules_by_id = {r.get("id"): r for r in rules if r.get("id")}
        for result in run.get("results", []):
            rule = _rule_for(result, rules, rules_by_id)
            level = _level_for(result, rule)
            if level == "none":
                continue  # a passed/informational check, not a finding

            props = {**result.get("properties", {})}
            rule_props = rule.get("properties", {})

            severity = _security_severity_score(props) or _security_severity_score(rule_props)
            if severity is None:
                # Bandit's SARIF preserves its own LOW/MEDIUM/HIGH scale --
                # more precise than the generic 4-value `level`.
                issue_severity = props.get("issue_severity")
                severity = (
                    {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(issue_severity)
                    if issue_severity
                    else _LEVEL_TO_SEVERITY.get(level, "medium")
                )

            file_path, line = _location(result, base_dir)

            rule_id = result.get("ruleId", "unknown")
            findings.append(
                Finding(
                    repository=repository,
                    file=file_path,
                    line=line,
                    scanner=scanner,
                    rule_id=rule_id.rsplit(".", 1)[-1] if "." in rule_id and "/" not in rule_id else rule_id,
                    severity=severity,
                    category=category,
                    message=_message_text(result.get("message")) or rule_id,
                    remediation=remediation_hint,
                )
            )
    return findings


def _message_text(message) -> str:
    # SARIF 2.1.0 requires `message` to be an object with a `text` property
    # -- but .NET's own `/p:ErrorLog=` SARIF logger emits a bare string
    # instead (verified against a real `dotnet build` run; see
    # scanners/security_code_scan.py), so both shapes have to be handled.
    if isinstance(message, str):
        return message.strip()
    if isinstance(message, dict):
        return (message.get("text") or "").strip()
    return ""
