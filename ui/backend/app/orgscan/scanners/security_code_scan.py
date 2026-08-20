"""Security Code Scan -- .NET SAST, distributed as a Roslyn analyzer NuGet
package rather than a standalone CLI. This adapter injects a temporary
`Directory.Build.props` referencing `SecurityCodeScan.VS2019` into the
cloned repo (never the user's real checkout -- org scans always operate on
a disposable clone), then runs `dotnet build /p:ErrorLog=<path>.sarif`,
which makes the C# compiler itself emit a native SARIF log of every
analyzer diagnostic, SCS's included. That SARIF is parsed via the same
generic `normalize.parse_sarif` used for checkov/semgrep/gosec.

Requires `dotnet restore` to reach NuGet during the build -- like SpotBugs,
a repo that can't build offline is a real, expected failure mode, and
`ScannerExecutionError` from a failed build surfaces as a per-scanner skip
rather than crashing the whole repo scan.

Verified against a real .NET 8 SDK (Docker image build): the SARIF this
logger emits deviates from spec on two points even with `version=2.1`
explicitly requested -- `message` is a bare string instead of a `{"text":
...}` object, and locations use the pre-2.1 `resultFile` shape with
absolute `file://` URIs instead of `physicalLocation`/repo-relative paths.
`normalize.parse_sarif` handles both (see its `_message_text`/`_location`
helpers); `base_dir=repo_dir` below is what makes the absolute URIs come
out repo-relative.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from ..models import Finding
from ..normalize import parse_sarif
from .base import ScannerExecutionError, require, run_capture

SCANNER_ID = "security_code_scan"

_DIRECTORY_BUILD_PROPS = """<Project>
  <ItemGroup>
    <PackageReference Include="SecurityCodeScan.VS2019" Version="5.6.7" PrivateAssets="all" />
  </ItemGroup>
</Project>
"""


def run(repo_dir: Path, repository: str) -> list[Finding]:
    require("dotnet")

    props_path = repo_dir / "Directory.Build.props"
    injected = not props_path.exists()
    if injected:
        props_path.write_text(_DIRECTORY_BUILD_PROPS)

    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
        out_path = tmp.name
    try:
        run_capture(
            ["dotnet", "build", f"/p:ErrorLog={out_path},version=2.1", "--nologo"],
            cwd=repo_dir,
            ok_exit_codes=(0, 1),
            timeout=1200,
        )
        sarif_path = Path(out_path)
        if not sarif_path.exists() or sarif_path.stat().st_size == 0:
            raise ScannerExecutionError("dotnet build did not produce a SARIF log")
        sarif_text = sarif_path.read_text()
    finally:
        Path(out_path).unlink(missing_ok=True)
        if injected:
            props_path.unlink(missing_ok=True)

    return parse_sarif(
        sarif_text,
        repository=repository,
        scanner=SCANNER_ID,
        category="sast",
        remediation_hint="See the Security Code Scan rule docs (security-code-scan.github.io) for the fix pattern.",
        base_dir=repo_dir,
    )
