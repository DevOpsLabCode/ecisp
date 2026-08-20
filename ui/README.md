# ecisp-ui

A web UI for the [Enterprise Cloud Discovery Engine](../README.md): configure a
provider scan, launch it, and browse the findings without touching the CLI.

> A **DevOps Lab** product. Author: **Stan Zvenigorodskiy**.

- `backend/` — FastAPI service that imports the engine's `run()` function
  directly from this repo and manages a scan job queue.
- `frontend/` — React + Vite dashboard: provider/auth form, scan history,
  and a findings browser (severity filters, per-service breakdown, expandable
  finding detail with affected resources).

## Scanning many accounts at once

Two ways, matched to what the engine actually supports natively:

- **Whole organization, one credential** — GCP (`organization_id` +
  "scan entire organization") and Azure ("scan entire organization") support
  this directly in the engine; both are scope-field toggles right on the New
  Scan form. AWS has no equivalent flag in this engine.
- **Bulk import** (New scan sidebar → Import accounts) — upload a CSV, XLSX,
  or JSON file where each row is one account's full scan configuration.
  Rows can mix providers in one file (some AWS rows, some Azure rows, etc.);
  only the columns relevant to each row's provider are used. Download a
  filled-in template from the import page. Invalid rows are skipped
  individually and reported, not treated as a reason to fail the whole
  import. See `ui/backend/app/batch_import.py`.

  For **AWS** specifically, "one credential, every account in the org" is a
  standard AWS SDK feature, not something this engine or UI needs to
  implement: configure per-account profiles in the backend's
  `~/.aws/config` using cross-account role assumption (`role_arn` +
  `source_profile`), then list each profile name in its own bulk-import row.
  boto3 (which the engine uses) resolves that chain automatically — see
  `EnterpriseCloudDiscovery/providers/aws/authentication_strategy.py`,
  which just does `boto3.Session(profile_name=profile)`.

## Org-wide GitHub security scanning (SAST)

Separate from the cloud provider scanning above: `New org scan` discovers
every repository in a GitHub organization or personal account (given a PAT),
clones each one, and runs whichever of eight SAST scanners actually apply to
what it finds in that repo:

| Scanner | Covers | Detected via |
|---|---|---|
| Checkov | Terraform, CloudFormation, Kubernetes, Dockerfiles | `.tf`, `Dockerfile`, IaC-shaped YAML |
| Bandit | Python | `.py` files / `requirements.txt` / `pyproject.toml` |
| Semgrep | Multi-language (bundled ruleset, see below) | any recognized source file |
| Gosec | Go | `go.mod` |
| SpotBugs | Java (compiles via Maven/Gradle first) | `pom.xml` / `build.gradle` |
| ESLint + eslint-plugin-security | JS/TS | `.js`/`.ts` files / `package.json` |
| Brakeman | Ruby on Rails | `Gemfile` / `config/application.rb` |
| Security Code Scan | .NET (via `dotnet build`) | `.csproj` / `.sln` |

Findings are deduplicated (same repo/file/rule/line collapses to one,
scanner attribution merges), and every scan produces all five report formats
— SARIF, JSON, CSV, HTML, PDF — downloadable from the scan detail page.
Critical/High findings can optionally open a grouped GitHub Issue per
repository (re-running the same day reuses the existing issue rather than
duplicating it); everything else always shows up in the reports regardless.
An optional notify email gets the summary + all five reports attached once
the scan finishes (configure `SMTP_HOST`/`SMTP_PORT`/`SMTP_USERNAME`/
`SMTP_PASSWORD`/`SMTP_FROM`/`SMTP_USE_TLS` on the backend; without them the
scan still runs and reports are still downloadable, the email step is just
skipped).

The PAT is used once for that scan and is never persisted. See
`ui/backend/app/orgscan/` — `github_client.py` (discovery/clone/issues,
works against both real GitHub Organizations and personal accounts),
`tech_detect.py` (which scanners apply to a given repo),
`repo_scanner.py`/`org_scan_job.py` (orchestration), `normalize.py` (the
shared SARIF→Finding conversion five of the eight scanners go through), and
`scanners/` (one adapter module per tool). Semgrep runs against a small
bundled ruleset (`orgscan/rulesets/semgrep-default.yml`) rather than
`--config auto`, deliberately avoiding a hard runtime dependency on the
Semgrep Registry being reachable; override with the `SEMGREP_CONFIG` env var.

This needs the full scanner toolchain (Go, JVM+Maven, Ruby, .NET SDK,
Node+ESLint) that only the Docker image installs — running the backend
directly with `uvicorn` (see below) will report every scanner as "not
installed" and just skip them for every repo, which is still safe (a scan
completes with empty results) but not useful. Use the Docker image, or
`ui/scripts/test-all.sh --docker`, to actually exercise this feature.

## Code scanning (upload / repo URL, SAST + SCA + Secrets + IaC + DAST)

A second entry point into the same scanner pipeline, scoped to a single
codebase instead of a whole org: `New code scan` accepts either an uploaded
`.zip`/`.tar`/`.tar.gz`/`.tgz` archive or a GitHub repository URL, and runs
it through the identical SAST/SCA/Secrets/IaC scanners as org-wide scanning
above, plus Trivy (dependency vulnerabilities + hardcoded secrets, one pass)
and an optional DAST follow-up against a live application URL.

**Upload flow**: the archive is extracted under strict containment checks
before anything else runs — zip-slip/tar-slip path traversal, symlinks,
hardlinks, device-special members, and oversized members/totals are all
rejected outright (`app/codescan/archive_extract.py`), and the archive is
never executed, only read. SpotBugs and Security Code Scan are skipped for
uploads specifically, since both require compiling the target
(`mvn`/`gradle`/`dotnet build`) — running an anonymous upload's own build
tooling would mean executing untrusted code, which this flow explicitly
does not do. They still run normally for the repo-URL flow.

**Repo URL flow**: public repos scan with no authentication at all. Private
repos need a "Connect GitHub" click, which opens the standard GitHub OAuth
Authorization Code flow in the browser — the user approves access on
github.com itself and is redirected back; the access token is exchanged
server-side and held only in an httponly session cookie, never in a URL, a
form field, or anywhere the frontend JS can read it. Branch selection is
available before scanning, and the exact commit SHA that was scanned is
recorded on the result either way.

**DAST**: once a source scan (upload or repo) completes, optionally supply
an authorized running application URL to run OWASP ZAP's automation
framework (spider → passive scan → active scan → passive scan → SARIF
report) against it. DAST findings merge into the same result and report as
the source scan — one dashboard, one set of downloadable reports, not two
separate outputs.

Both source flows and DAST all funnel through the same
`normalize.parse_sarif()` → `Finding` → report pipeline org-wide scanning
uses, so the same five formats (SARIF, JSON, CSV, HTML, PDF) are available
per scan, plus in-app Critical/High/Medium/Low findings display.

Endpoints (`ui/backend/app/main.py`): `POST /api/code-scans/upload`,
`GET /api/code-scans/branches?repo_url=...`, `POST /api/code-scans/repo`,
`GET /api/code-scans` / `GET /api/code-scans/{id}`,
`POST /api/code-scans/{id}/dast`, `GET /api/code-scans/{id}/report.{fmt}`,
and `GET|POST /api/github/oauth/*` for the Connect-GitHub flow. See
`ui/backend/app/codescan/` — `archive_extract.py` (safe extraction),
`code_scan_job.py` (orchestration, mirrors `orgscan/org_scan_job.py`'s
single-worker queue), `github_oauth.py` (the OAuth Authorization Code flow
and in-memory CSRF-state/session stores), and `dast_scanner.py` (the ZAP
automation-plan runner). Trivy's adapter lives alongside the other SAST
tools at `app/orgscan/scanners/trivy_sca_secrets.py` since it's reused by
both org-wide and single-repo scanning.

To enable the private-repo "Connect GitHub" button, register a GitHub OAuth
App (github.com/settings/developers → New OAuth App) with its callback URL
set to `<BACKEND_URL>/api/github/oauth/callback`, and set
`GITHUB_OAUTH_CLIENT_ID`/`GITHUB_OAUTH_CLIENT_SECRET` on the backend
(`FRONTEND_URL`/`BACKEND_URL` env vars control the redirect targets, and
default to this repo's own docker-compose ports). Without those two env
vars set, `is_configured()` is false and the button surfaces that state
instead of a broken login — public-repo scanning and uploads work
regardless.

Like org-wide scanning, this needs the full toolchain (plus Trivy and ZAP
specifically) that only the Docker image installs — see the Dockerfile's
`trivy-builder`/`zap-builder` stages.

## Container registry scanning

A third scan type, orthogonal to the two above: `New registry scan` scans
one **container image** — pulled straight from JFrog Artifactory, Docker
Hub, GitHub Container Registry, AWS ECR, Google Artifact Registry, Azure
ACR, Harbor, Quay.io, or any other registry that speaks the standard
Docker Registry HTTP API v2 / OCI Distribution Spec. This isn't
vendor-specific integration work: Trivy's `trivy image` command already
resolves an image reference against that standard protocol — the same one
`docker pull` speaks — so one code path covers every registry above, and
"and others" is free.

Give it an image reference (`myregistry.jfrog.io/docker-local/app:1.2.3`)
and, for private images, a username/password or registry token. Trivy
scans for both dependency vulnerabilities and hardcoded secrets in one
pass, the same as the code-scan pipeline's SCA step, and produces the same
five report formats plus an in-app findings browser.

Credentials are passed to the `trivy image` subprocess as environment
variables (`TRIVY_USERNAME`/`TRIVY_PASSWORD`/`TRIVY_REGISTRY_TOKEN`) —
verified live that Trivy's CLI binds these automatically — never as
command-line arguments (which `ps` on the host would expose) and never
persisted; used once for that scan and discarded. See
`ui/backend/app/registryscan/image_scanner.py` for the adapter and
`registry_scan_job.py` for the (simplest of the three) job queue.

Live-verified against real images: `alpine:3.18` (clean pull, 0 findings)
and `node:14.0.0` (3231 genuine CVE findings, real severities, real
report downloads) through the actual running Docker stack, not mocks.

## Runtime Defender (Golem)

A fourth, deliberately different kind of scan: instead of scanning a
snapshot (a repo, an org, an image), Runtime Defender watches a live
Kubernetes cluster for suspicious behavior as it happens — process
execution, sensitive file access, container drift — using
[Falco](https://falco.org), the CNCF eBPF-based runtime security sensor,
rather than anything custom-built.

**Install flow**: `Install Golem Defender` registers a cluster (just a
name) and returns a one-line `curl ... | bash` command with a unique
webhook URL and install token baked in. Run it against whichever cluster
your `kubectl` context points at — it `helm install`s the real Falco
chart plus [falcosidekick](https://github.com/falcosecurity/falcosidekick)
(which forwards Falco's alerts to arbitrary outputs; configured here with
its `webhook` output pointed back at this cluster's endpoint), and nothing
else. No agent to build, no custom kernel module.

**Why `driver.kind=modern_ebpf`**: Falco supports several ways to hook
into the kernel; `modern_ebpf` is the one that needs no kernel headers and
no privileged kernel-module loading (many managed/hardened clusters block
that), and every EKS/AKS/GKE/OpenShift default node image ships a kernel
new enough (5.8+) to run it. One driver choice covers all four distros —
the same "it's just Kubernetes" reasoning that made the registry scanner's
"any OCI registry" and the code scanner's "any git host" free.

**Detect-and-report only**: this is v1's deliberate scope. Falco alerts
flow in, get normalized into the same `Finding` shape every other scan
type uses, and accumulate against the cluster — nothing is ever blocked,
killed, or quarantined automatically. Unlike the other three scan types
(each models "kick off one run, it finishes"), a cluster's findings stream
in indefinitely, so this is a plain in-memory registry rather than a job
queue, and the five report formats are generated on demand from whatever
has accumulated so far rather than rewritten after every single alert.

**SCA correlation**: if a runtime alert names a container image that this
app has already scanned via registry scanning, the finding's remediation
gets a note naming the exact CVE count and severity breakdown for that
image — "this container is running image X, which a registry scan found
to have 14 known vulnerabilities: 4 high, 8 medium, 2 low." That's a plain
join across two data sets this app already has (a running container's
exact image reference, and that image's own SCA results), not a
vendor integration.

Every Falco priority level maps onto the same five-level severity scale
the rest of the app uses (Critical/Alert/Emergency → critical, Error →
high, Warning → medium, Notice → low, Informational/Debug → info; an
unrecognized priority falls back to medium rather than crashing).

Live-verified end to end against a real local `kind` cluster: real Falco
+ falcosidekick Helm install, a real attack (`cat /etc/shadow` inside a
pod) detected by the real eBPF sensor, delivered through a real webhook
POST into the running backend, and — for the correlation feature — a real
registry scan of `alpine:3.9` (14 genuine CVEs) whose results showed up
verbatim in the next runtime alert's remediation text, confirmed both via
the API and rendered in the actual UI.

## How it fits together

The backend does **not** shell out to the `enterprise-cloud-discovery` CLI —
it imports `EnterpriseCloudDiscovery.__main__.run()` in-process and calls it
with keyword arguments built from the scan request. Scans run one at a time
on a single background worker thread (the engine's logger setup and asyncio
event loop are process-global, so concurrent runs aren't safe). Results are
read back off disk after a run completes, using the engine's own
`JavaScriptEncoder` to parse the `enterprise_cloud_discovery_results_*.js`
report file.

## Setup

The engine requires **Python 3.9–3.11** (see [../README.md#requirements](../README.md#requirements)).

```bash
cd ui/backend
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt   # installs the engine editable from ../../, plus FastAPI
uvicorn app.main:app --reload --port 8000
```

In a second terminal:

```bash
cd ui/frontend
npm install
npm run dev
```

Open http://localhost:5173. The frontend talks to the backend at
`http://localhost:8000` by default; override with `VITE_API_URL` if needed.

### Running without the engine installed

The backend boots fine even if the engine package (and its many cloud SDK
dependencies) isn't installed — `/api/health` reports `engine_available` and
`/api/providers` still serves the form metadata. Launching a scan will queue
and then fail cleanly with an explanatory error. This is intentional so the
UI itself can be developed/tested independent of a full 3.9–3.11 cloud-SDK
environment.

### Docker

The real way to run this: two images, brought up together.

```bash
cd ui
docker compose up --build
```

- Backend: http://localhost:8000 (full engine installed — this actually
  builds `EnterpriseCloudDiscovery` and its complete dependency tree, ~2GB
  image, several minutes on a cold build)
- Frontend: http://localhost:8080

The backend `Dockerfile` builds from the **repo root** (not `ui/backend`) —
it needs `EnterpriseCloudDiscovery/` alongside the FastAPI layer, and
`engine_runner.py` locates the engine via a path relative to its own file,
so the in-container layout mirrors the repo layout exactly. It's a
multi-stage build: a `builder` stage with a compiler toolchain (some cloud
SDK transitive deps don't ship wheels for every platform) produces a venv,
and the `runtime` stage copies just that venv in, so the final image doesn't
carry a gcc toolchain.

The frontend bakes `VITE_API_URL` in at build time (Vite env vars aren't
runtime-configurable) — it must point wherever the backend is reachable
*from the browser*, not container-to-container. Override with
`VITE_API_URL=https://your-host:8000 docker compose up --build` if you're
not using the default port-mapped localhost setup.

## Testing

**Fastest way to check everything:** `ui/scripts/test-all.sh` runs the same
checks as `ui-ci.yml`, locally, in the same order they'd fail in CI:

```bash
ui/scripts/test-all.sh            # backend + frontend lint/SAST/tests/build (~1 min)
ui/scripts/test-all.sh --docker   # + builds the real Docker stack, brings it
                                   # online, and runs a real scan job through
                                   # the engine (~5 min, needs Docker)
```

The `--docker` run is the only one that exercises the engine's `run()` at
all — everything else (including the plain unit test suites below) stubs
or never touches it. It's what caught the worker-thread asyncio bug
mentioned above; don't skip it before anything that touches `jobs.py`,
`engine_runner.py`, or the Dockerfiles.

Requires `python3.11` (`brew install python@3.11` if you don't have it —
newer Python versions can't build `pydantic-core` from source since PyO3
doesn't support them yet) and Node ≥22.22.2 for the frontend half; `--docker`
additionally needs Docker running (Docker Desktop, or `colima start` on
macOS without it).

### Manually, piece by piece

Both halves have unit test suites enforced at **95% coverage** in CI (line/statement/function coverage; branch coverage is also gated at 95%, with any genuinely unreachable defensive branches marked `pragma: no cover` / left as documented exceptions rather than papered over with contrived tests).

```bash
# Backend -- stubs out EnterpriseCloudDiscovery (see tests/conftest.py), so
# this only needs requirements-test.txt, not the real engine.
cd ui/backend
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements-test.txt
pytest                          # runs with --cov, fails under 95%

# Frontend
cd ui/frontend
npm install
npm run test:coverage           # vitest + v8 coverage, fails under 95%
```

Lint/security tooling (also run in CI):

```bash
# Backend
pip install -r requirements-dev.txt
ruff check .                    # lint
bandit -r app -c pyproject.toml # SAST

# Frontend
npm run lint                    # oxlint
npx tsc -b --noEmit              # typecheck
```

## CI/CD

Two workflows under `.github/workflows/`, both scoped to `ui/**` so they don't run on engine-only changes:

- **`ui-ci.yml`** — backend tests+coverage, backend lint (ruff), backend SAST
  (bandit), frontend tests+coverage, frontend lint+typecheck, frontend build,
  dependency + secret scanning (Trivy, both ecosystems, SARIF uploaded to
  the Security tab), and performance scanning:
  - `perf-frontend`: Lighthouse CI against the production build (performance/accessibility/best-practices/SEO score budgets, see `frontend/lighthouserc.json`)
  - `perf-backend`: a k6 smoke/latency test (`perf/k6-backend-smoke.js`) against `/api/health` and `/api/providers` — this only exercises the always-available metadata endpoints (CI has no cloud credentials to run a real scan against), asserting p95/p99 latency budgets and a zero error rate. It's a regression guard on the API layer itself, not a substitute for load-testing a real deployment.
  - A final `ci-summary` job fans in every other job so branch protection only needs one required check.
- **`ui-codeql.yml`** — CodeQL static analysis for both `javascript-typescript` and `python`, on push/PR plus a weekly schedule.
- **`ui-deploy.yml`** — builds both Docker images, brings the real stack
  online with `docker compose`, and smoke-tests it before publishing:
  - health/providers checks against the live backend
  - a **real scan job** through a bogus AWS profile, asserting the engine
    actually ran and failed on its own auth check rather than crashing
    inside our integration (`perf/assert_scan_ran.py`) — this is the only
    check that exercises the engine's `run()` at all; the metadata
    endpoints never touch it. It's what caught a real bug during
    development: the job-queue's background worker thread had no asyncio
    event loop, which the engine's `run()` needs and Python 3.10+ no
    longer creates implicitly for non-main threads. Every real scan would
    have failed in production without this. See `JobManager._run_worker`.
  - the k6 latency smoke test, against the live containers
  - only publishes to GHCR (`ghcr.io/<owner>/<repo>-backend` /
    `-frontend`, tagged with the commit SHA, plus `:latest` on `main`) if
    every check above passed — pull-request runs build and test but never
    publish.

### Verifying the pipeline itself

If you change a workflow file, don't just eyeball it -- YAML that parses
is not YAML that runs:

```bash
brew install actionlint    # validates syntax AND checks that pinned action
                            # tags/inputs actually exist and resolve
actionlint .github/workflows/*.yml
```

That last part matters: `actionlint` is what would have caught
`aquasecurity/trivy-action@0.29.0` (missing the `v` real tags use) before
it ever reached CI. After pushing, watch it run rather than assuming green:

```bash
gh pr checks <PR#>              # one-line pass/fail per check
gh run watch <run-id> --exit-status   # live tail of a specific run
```

## Notes / follow-ups worth knowing about

- **Reports directory**: scan output is written to `ui/backend/data/reports`.
  Nothing prunes it — treat it as evidence storage and manage retention
  yourself per the engine README's guidance.
- **One scan at a time**: by design (see above). If you need concurrency,
  the real fix is running multiple engine processes/workers, not multiple
  threads in this backend.
- **No auth on the backend API**: it binds to localhost only in dev. Don't
  expose `uvicorn` beyond localhost without adding authentication in front of
  it — scan credentials and results are sensitive.
- **SQLite result format isn't wired up** — the UI always requests
  `result_format=json` since that's what it reads back. The engine's
  experimental SQLite/`--serve` path isn't exposed here.
- **Org-scan reports directory**: written to `ui/backend/data/orgscan-reports`,
  same "nothing prunes it, manage retention yourself" caveat as above. Not
  currently mounted as a named volume in `docker-compose.yml` (the cloud-scan
  `reports` volume is), so org-scan reports don't survive a container
  recreate — fine for local use, worth fixing before relying on it in a real
  deployment.
- **One org scan at a time, fanned out internally**: same single-worker-queue
  shape as cloud scans, for the same reason (process-global state) — but each
  org scan clones/scans its own repos concurrently via a thread pool
  (`max_workers`), so this isn't as serial as it sounds for a single scan.
- **Code-scan reports/uploads directories**: written to
  `ui/backend/data/codescan-reports` and `codescan-uploads` respectively
  (the latter is emptied per-scan — uploaded archives are deleted once
  extraction finishes, successfully or not). Same "nothing prunes the
  reports, not a named volume, won't survive a container recreate" caveats
  as org-scan above.
- **GitHub OAuth sessions are in-memory, like every other job manager here**:
  restarting the backend logs everyone's "Connect GitHub" session out (they
  just click it again) — a deliberate scope choice, not an oversight, matching
  how scan/org-scan/batch state is all in-memory too.
- **Registry-scan reports directory**: written to
  `ui/backend/data/registryscan-reports`, same "nothing prunes it, not a
  named volume, won't survive a container recreate" caveats as the other
  two report directories above.
- **Runtime Defender clusters/findings are in-memory, like every other job
  manager here**: restarting the backend forgets every registered cluster,
  install token, and accumulated finding — a running Falco DaemonSet will
  keep POSTing to a webhook URL that now 404s until the cluster is
  re-registered and pointed at the new install command. No report
  directory either: reports are generated on demand from whatever's
  currently in memory, so there's nothing to prune in the first place.
