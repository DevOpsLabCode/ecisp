// Lightweight performance smoke test for the ecisp-ui backend API.
//
// This does NOT exercise real cloud scans (CI has no cloud credentials) --
// it hits the always-available metadata endpoints (/api/health,
// /api/providers) under light concurrency and asserts basic latency and
// error-rate budgets. It's a regression guard against the API layer itself
// getting slow (e.g. an accidental synchronous call on the request path),
// not a substitute for load-testing a real deployment against production
// data volumes.
import http from "k6/http";
import { check, sleep } from "k6";

const BASE_URL = __ENV.BASE_URL || "http://localhost:8000";

export const options = {
  scenarios: {
    smoke: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "10s", target: 10 },
        { duration: "20s", target: 10 },
        { duration: "5s", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ["rate==0"],
    http_req_duration: ["p(95)<500", "p(99)<1000"],
    "http_req_duration{endpoint:health}": ["p(95)<200"],
    "http_req_duration{endpoint:providers}": ["p(95)<300"],
  },
};

export default function () {
  const health = http.get(`${BASE_URL}/api/health`, { tags: { endpoint: "health" } });
  check(health, { "health status is 200": (r) => r.status === 200 });

  const providers = http.get(`${BASE_URL}/api/providers`, { tags: { endpoint: "providers" } });
  check(providers, {
    "providers status is 200": (r) => r.status === 200,
    "providers returns all 7 providers": (r) => JSON.parse(r.body).length === 7,
  });

  sleep(1);
}
