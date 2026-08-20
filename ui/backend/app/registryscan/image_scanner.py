"""Container registry image scanning -- vulnerabilities and secrets baked
into an image, pulled directly from any OCI/Docker-v2-compliant registry:
JFrog Artifactory, Docker Hub, GitHub Container Registry, AWS ECR, Google
Artifact Registry, Azure ACR, Harbor, Quay.io, and self-hosted Nexus/Harbor
instances -- the same `trivy image` invocation covers all of them, since
none of this is vendor-specific: Trivy resolves the image reference against
the registry's standard Docker Registry HTTP API v2 / OCI Distribution
Spec, the same protocol `docker pull` itself speaks.

Verified against real images (`trivy image` 0.74.0, no local Docker
daemon needed -- it pulls layers directly over the registry API):
`alpine:3.18` (clean, 0 findings, proves the success-with-no-findings
path), `node:14.0.0` (3231 real CVE findings, proves real detection), and
a deliberately-wrong-credentials pull against a private image (clean
FATAL error on stderr, nonzero exit, no output file -- proves the
failure path doesn't silently succeed).

Credentials are passed as environment variables (`TRIVY_USERNAME` /
`TRIVY_PASSWORD` / `TRIVY_REGISTRY_TOKEN`), not CLI arguments -- verified
live that Trivy's cobra/viper CLI binds every registry flag to an
uppercased `TRIVY_`-prefixed env var (only `--password` documents this in
`--help`, but `TRIVY_USERNAME` was confirmed to work too), which keeps
every credential out of the process argv `ps` would otherwise expose.
Never logged, never persisted -- used once for this scan and discarded.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 -- fixed `trivy image ...` invocation, no shell, credentials via env not argv
import tempfile
from pathlib import Path

from ..orgscan.models import Finding
from ..orgscan.normalize import parse_sarif
from ..orgscan.scanners.base import ScannerExecutionError, ScannerUnavailable, require

SCANNER_ID = "trivy"


def _category_for(result: dict, rule: dict) -> str:
    tags = rule.get("properties", {}).get("tags", [])
    return "secrets" if "secret" in tags else "sca"


def run_registry_scan(
    image_ref: str,
    username: str | None = None,
    password: str | None = None,
    registry_token: str | None = None,
    insecure: bool = False,
    timeout: int = 1200,
) -> list[Finding]:
    """Pulls `image_ref` from its registry and scans it for known
    vulnerabilities and hardcoded secrets. Raises `ScannerUnavailable` if
    trivy isn't installed, `ScannerExecutionError` if the pull or scan
    fails (bad credentials, unknown image/tag, unreachable registry)."""
    require("trivy")

    env = os.environ.copy()
    if username:
        env["TRIVY_USERNAME"] = username
    if password:
        env["TRIVY_PASSWORD"] = password
    if registry_token:
        env["TRIVY_REGISTRY_TOKEN"] = registry_token

    args = ["trivy", "image", "--scanners", "vuln,secret", "--format", "sarif"]
    if insecure:
        args.append("--insecure")

    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
        out_path = tmp.name
    try:
        try:
            proc = subprocess.run(  # nosec B603
                [*args, "--output", out_path, image_ref],
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ScannerUnavailable(str(exc)) from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerExecutionError(f"trivy image scan timed out after {timeout}s") from exc

        sarif_path = Path(out_path)
        if proc.returncode != 0 or not sarif_path.exists() or sarif_path.stat().st_size == 0:
            raise ScannerExecutionError(f"could not scan '{image_ref}': {proc.stderr[-2000:] or proc.stdout[-2000:]}")
        sarif_text = sarif_path.read_text()
    finally:
        Path(out_path).unlink(missing_ok=True)

    return parse_sarif(
        sarif_text,
        repository=image_ref,
        scanner=SCANNER_ID,
        category="sca",  # overridden per-result by category_fn below
        remediation_hint="For vulnerabilities, upgrade to the fixed version named in the message. For secrets, "
        "rotate the credential immediately and rebuild the image without it baked in.",
        category_fn=_category_for,
    )
