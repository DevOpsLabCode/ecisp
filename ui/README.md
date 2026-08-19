# ecisp-ui

A web UI for the [Enterprise Cloud Discovery Engine](../README.md): configure a
provider scan, launch it, and browse the findings without touching the CLI.

- `backend/` — FastAPI service that imports the engine's `run()` function
  directly from this repo and manages a scan job queue.
- `frontend/` — React + Vite dashboard: provider/auth form, scan history,
  and a findings browser (severity filters, per-service breakdown, expandable
  finding detail with affected resources).

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
