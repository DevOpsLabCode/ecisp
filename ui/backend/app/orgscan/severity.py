"""Maps each scanner's own severity vocabulary onto the common
critical/high/medium/low/info scale, so findings from eight different
tools can be sorted, counted, and thresholded (e.g. "auto-create issues for
Critical/High") consistently.
"""
from __future__ import annotations

_CHECKOV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}

# Bandit has no severity->category split the way others do; its own
# severity field (LOW/MEDIUM/HIGH) already matches our scale directly.
_BANDIT = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

_SEMGREP = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}

_GOSEC = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

# SpotBugs uses a 1-20 "rank" (lower = more severe) as well as a
# priority (1/2/3); we use priority since it's the field most SpotBugs
# configurations actually surface.
_SPOTBUGS_PRIORITY = {1: "high", 2: "medium", 3: "low"}

# ESLint's own severity is just warn(1)/error(2); the security plugin's
# rules don't carry finer-grained severity, so error findings map to high
# and warnings to medium -- conservative, since a lint "warning" from a
# *security* rule is still worth a human look.
_ESLINT = {2: "high", 1: "medium"}

# Brakeman confidence: High/Medium/Weak.
_BRAKEMAN = {"High": "high", "Medium": "medium", "Weak": "low"}

# Security Code Scan / Roslyn analyzer diagnostic severity.
_ROSLYN = {"Error": "high", "Warning": "medium", "Info": "info"}


def checkov(raw: str) -> str:
    return _CHECKOV.get((raw or "").upper(), "medium")


def bandit(raw: str) -> str:
    return _BANDIT.get((raw or "").upper(), "medium")


def semgrep(raw: str) -> str:
    return _SEMGREP.get((raw or "").upper(), "medium")


def gosec(raw: str) -> str:
    return _GOSEC.get((raw or "").upper(), "medium")


def spotbugs(priority: int) -> str:
    return _SPOTBUGS_PRIORITY.get(priority, "medium")


def eslint(raw_severity: int) -> str:
    return _ESLINT.get(raw_severity, "medium")


def brakeman(raw: str) -> str:
    return _BRAKEMAN.get(raw, "medium")


def roslyn(raw: str) -> str:
    return _ROSLYN.get(raw, "medium")
