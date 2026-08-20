"""Detects which technologies a repository checkout uses, so only the
scanners relevant to it run -- scanning a pure-frontend repo with Bandit
(Python) or a pure-Python repo with Gosec (Go) wastes time and produces
nothing but noise.

Detection is indicator-file based and intentionally shallow (a handful of
`Path.rglob` calls capped in depth by `MAX_SCAN_DEPTH`) -- good enough to
route to the right scanners without turning technology detection itself
into a slow full-tree walk on a huge monorepo.
"""
from __future__ import annotations

from pathlib import Path

MAX_SCAN_DEPTH = 4

# scanner id -> glob patterns whose presence (anywhere within
# MAX_SCAN_DEPTH) means that scanner should run against this repo.
INDICATORS: dict[str, list[str]] = {
    "checkov": ["*.tf", "*.tf.json", "Dockerfile", "cloudformation*.yml", "cloudformation*.yaml", "*.yaml", "*.yml"],
    "bandit": ["requirements*.txt", "pyproject.toml", "setup.py", "Pipfile"],
    "semgrep": ["*"],  # multi-language; always applicable if anything else matched, gated separately below
    "gosec": ["go.mod"],
    "spotbugs": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "eslint_security": ["package.json"],
    "brakeman": ["Gemfile", "config/application.rb"],
    "security_code_scan": ["*.csproj", "*.sln"],
}

# Checkov's `*.yaml`/`*.yml` indicator is deliberately broad (Kubernetes
# manifests have no fixed filename) -- but that means it fires for repos
# that just happen to ship an unrelated YAML file (CI config, docs
# front-matter). Require the file to actually look like IaC before
# counting it as a checkov signal.
_IAC_YAML_HINTS = ("apiVersion:", "kind:", "AWSTemplateFormatVersion", "Resources:")


def _looks_like_iac_yaml(path: Path) -> bool:
    try:
        head = path.read_text(errors="ignore")[:2000]
    except OSError:
        return False
    return any(hint in head for hint in _IAC_YAML_HINTS)


def _walk(repo_dir: Path, max_depth: int = MAX_SCAN_DEPTH):
    root_depth = len(repo_dir.parts)
    for p in repo_dir.rglob("*"):
        if p.is_dir():
            continue
        if any(part in {".git", "node_modules", "vendor", ".venv", "dist", "build"} for part in p.parts):
            continue
        if len(p.parts) - root_depth > max_depth:
            continue
        yield p


def detect(repo_dir: Path) -> list[str]:
    """Returns the sorted list of scanner ids that should run against repo_dir."""
    files = list(_walk(repo_dir))
    names = {p.name for p in files}
    suffixes = {p.suffix for p in files}

    detected: set[str] = set()

    if (
        names & {"requirements.txt", "pyproject.toml", "setup.py", "Pipfile"}
        or any(n.startswith("requirements") and n.endswith(".txt") for n in names)
        or ".py" in suffixes
    ):
        detected.add("bandit")

    if any(p.suffix in {".tf"} for p in files) or "Dockerfile" in names:
        detected.add("checkov")
    else:
        for p in files:
            if p.suffix in {".yaml", ".yml"} and _looks_like_iac_yaml(p):
                detected.add("checkov")
                break

    if "go.mod" in names:
        detected.add("gosec")

    if names & {"pom.xml", "build.gradle", "build.gradle.kts"}:
        detected.add("spotbugs")

    if "package.json" in names or suffixes & {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        detected.add("eslint_security")

    if "Gemfile" in names or (repo_dir / "config" / "application.rb").exists():
        detected.add("brakeman")

    if suffixes & {".csproj", ".sln"}:
        detected.add("security_code_scan")

    # Semgrep is multi-language and cheap to point at any repo that has
    # source code at all, so it rides along with any other match rather
    # than needing its own indicator file.
    code_suffixes = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".cs", ".tf"}
    if detected or (suffixes & code_suffixes):
        detected.add("semgrep")

    return sorted(detected)
