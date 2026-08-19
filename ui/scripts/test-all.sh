#!/usr/bin/env bash
# Runs the same checks as ui-ci.yml / ui-deploy.yml, locally, in the same
# order they'd fail in CI. Fails fast on the first broken thing.
#
# Usage:
#   ui/scripts/test-all.sh            # unit tests, lint, SAST, build (~1 min)
#   ui/scripts/test-all.sh --docker   # also builds+runs the real Docker
#                                      # stack and smoke-tests it (~5+ min,
#                                      # needs Docker; this is what actually
#                                      # exercises the engine's run())
#
# Requires: python3.11 (or a venv pointed at it), node >=22.22.2, docker
# (only for --docker).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI_DIR="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$UI_DIR/backend"
FRONTEND_DIR="$UI_DIR/frontend"

RUN_DOCKER=false
for arg in "$@"; do
  case "$arg" in
    --docker) RUN_DOCKER=true ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$1"; }

# ---------------------------------------------------------------------
# Backend: venv, lint, SAST, tests + coverage gate
# ---------------------------------------------------------------------
step "Backend: setting up venv"
cd "$BACKEND_DIR"
if [ ! -d .venv ]; then
  python3.11 -m venv .venv || python3 -m venv .venv
fi
# shellcheck source=/dev/null
source .venv/bin/activate
pip install -q -r requirements-dev.txt  # pulls in requirements-test.txt too
ok "backend deps installed"

step "Backend: ruff"
ruff check .
ok "ruff clean"

step "Backend: bandit (SAST)"
bandit -r app -c pyproject.toml
ok "bandit clean"

step "Backend: pytest (>=95% coverage gate)"
pytest
ok "backend tests + coverage passed"

deactivate

# ---------------------------------------------------------------------
# Frontend: lint, typecheck, tests + coverage gate, build
# ---------------------------------------------------------------------
step "Frontend: npm ci"
cd "$FRONTEND_DIR"
node_major="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$node_major" -lt 22 ]; then
  echo "Node >=22.22.2 required (jsdom's requirement) -- found $(node -v)" >&2
  exit 1
fi
npm ci
ok "frontend deps installed"

step "Frontend: lint (oxlint)"
npm run lint
ok "lint clean"

step "Frontend: typecheck"
npx tsc -b --noEmit
ok "typecheck clean"

step "Frontend: vitest (>=95% coverage gate)"
npm run test:coverage
ok "frontend tests + coverage passed"

step "Frontend: build"
npm run build
ok "build succeeded"

echo
ok "All fast checks passed."

if [ "$RUN_DOCKER" = false ]; then
  echo "Skipped the Docker/engine integration test -- rerun with --docker to include it."
  exit 0
fi

# ---------------------------------------------------------------------
# Docker: build the real stack, bring it online, smoke-test it
# ---------------------------------------------------------------------
step "Docker: building images"
cd "$UI_DIR"
docker compose build
ok "images built"

step "Docker: bringing the stack online"
docker compose up -d
trap 'docker compose logs; docker compose down -v' EXIT

step "Waiting for backend health"
for _ in $(seq 1 30); do
  curl -sf http://localhost:8000/api/health >/dev/null && break
  sleep 1
done
curl -sf http://localhost:8000/api/health
echo
ok "backend healthy"

step "Smoke test: /api/providers"
count=$(curl -sf http://localhost:8000/api/providers | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")
test "$count" = "7"
ok "7 providers registered"

step "Smoke test: a real scan job through the engine"
job_id=$(curl -sf -X POST http://localhost:8000/api/scans \
  -H 'content-type: application/json' \
  -d '{"provider":"aws","auth_method":"profile","auth":{"profile":"local-smoke-test-nonexistent"},"report_name":"local-smoke-scan"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
for _ in $(seq 1 30); do
  status=$(curl -sf "http://localhost:8000/api/scans/$job_id" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
  { [ "$status" = "completed" ] || [ "$status" = "failed" ]; } && break
  sleep 1
done
curl -sf "http://localhost:8000/api/scans/$job_id" > /tmp/ecisp-local-scan-detail.json
python3 "$UI_DIR/perf/assert_scan_ran.py" /tmp/ecisp-local-scan-detail.json
rm -f /tmp/ecisp-local-scan-detail.json

step "Smoke test: frontend"
curl -sf http://localhost:8080/ | grep -qi "ecisp"
ok "frontend serving"

if command -v k6 >/dev/null 2>&1; then
  step "k6 latency smoke test"
  BASE_URL=http://localhost:8000 k6 run "$UI_DIR/perf/k6-backend-smoke.js"
  ok "k6 thresholds passed"
else
  echo "k6 not installed (brew install k6) -- skipping latency test"
fi

echo
ok "All checks passed, including the real Docker stack."
