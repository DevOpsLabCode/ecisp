"""Thin HTTP client for the two Golem backend routes this component ever
calls -- GET /api/iam-revocation/commands and POST .../status. Both
authenticate with IAM_RESPONDER_API_KEY as a bearer token, a fleet-wide
credential entirely separate from any cluster's own install token (see
ui/backend/app/main.py's _authenticated_iam_component).
"""

from __future__ import annotations

import httpx

VALID_STATUSES = ("applied", "failed", "released")


class GolemBackendClient:
    def __init__(self, base_url: str, api_key: str, *, http_client: httpx.Client | None = None):
        self._base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {api_key}"}
        # A caller-supplied client lets tests inject an httpx.Client wired
        # to a local ASGI transport instead of a real network connection.
        self._client = http_client or httpx.Client(timeout=10.0)

    def list_commands(self) -> list[dict]:
        response = self._client.get(f"{self._base_url}/api/iam-revocation/commands", headers=self._headers)
        response.raise_for_status()
        return response.json()

    def report_status(self, command_id: str, status: str) -> None:
        if status not in VALID_STATUSES:
            raise ValueError(f"Unknown status {status!r}, expected one of {VALID_STATUSES}")
        response = self._client.post(
            f"{self._base_url}/api/iam-revocation/commands/{command_id}/status",
            headers=self._headers,
            json={"status": status},
        )
        response.raise_for_status()

    def close(self) -> None:
        self._client.close()
