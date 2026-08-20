"""GitHub OAuth Authorization Code flow for the private-repo "Connect
GitHub" button -- the user is redirected to github.com, approves access,
and GitHub redirects back to our own callback with a one-time code, which
this module exchanges server-side for an access token. The token never
touches the frontend or the URL bar; the browser only ever holds an
httponly session cookie that maps to it.

Requires a GitHub OAuth App (github.com/settings/developers -> New OAuth
App) with its callback URL set to this backend's
`/api/github/oauth/callback`, and its Client ID/Secret set as
GITHUB_OAUTH_CLIENT_ID/GITHUB_OAUTH_CLIENT_SECRET. Without those env vars,
`build_authorize_url` raises `OAuthNotConfigured` -- the rest of this
feature (upload scanning, public-repo scanning) works regardless, only the
private-repo path needs this configured.
"""

from __future__ import annotations

import os
import secrets
import time
from urllib.parse import urlencode

import httpx

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"  # nosec B105 -- a URL, not a credential; bandit pattern-matches the substring "access_token"
OAUTH_SCOPE = "repo"

STATE_TTL_SECONDS = 600  # 10 minutes -- just long enough for a real login, short enough to limit CSRF exposure
SESSION_TTL_SECONDS = 3600
SESSION_COOKIE_NAME = "golem_github_session"


class OAuthNotConfigured(Exception):
    """GITHUB_OAUTH_CLIENT_ID/SECRET aren't set."""


class OAuthError(Exception):
    """GitHub rejected the authorization code, or returned an error."""


def _client_id() -> str:
    value = os.environ.get("GITHUB_OAUTH_CLIENT_ID")
    if not value:
        raise OAuthNotConfigured("GITHUB_OAUTH_CLIENT_ID is not set")
    return value


def _client_secret() -> str:
    value = os.environ.get("GITHUB_OAUTH_CLIENT_SECRET")
    if not value:
        raise OAuthNotConfigured("GITHUB_OAUTH_CLIENT_SECRET is not set")
    return value


def is_configured() -> bool:
    return bool(os.environ.get("GITHUB_OAUTH_CLIENT_ID")) and bool(os.environ.get("GITHUB_OAUTH_CLIENT_SECRET"))


def build_authorize_url(redirect_uri: str, state: str) -> str:
    params = {
        "client_id": _client_id(),
        "redirect_uri": redirect_uri,
        "scope": OAUTH_SCOPE,
        "state": state,
    }
    return f"{AUTHORIZE_URL}?{urlencode(params)}"


def exchange_code(code: str, redirect_uri: str, transport: httpx.BaseTransport | None = None) -> str:
    """Trades a one-time authorization code for an access token. This is
    the one call in the whole flow that talks to GitHub server-to-server --
    the token it returns never passes through the browser."""
    with httpx.Client(transport=transport, timeout=15.0) as client:
        resp = client.post(
            TOKEN_URL,
            data={
                "client_id": _client_id(),
                "client_secret": _client_secret(),
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        body = resp.json()

    if "error" in body:
        raise OAuthError(body.get("error_description") or body["error"])
    token = body.get("access_token")
    if not token:
        raise OAuthError("GitHub's token response had no access_token")
    return token


class _TTLStore:
    """Minimal in-memory expiring key/value store, shared shape for both
    the CSRF state tokens (short-lived, single-use) and the post-login
    sessions (longer-lived, reusable until expiry). In-memory is a
    deliberate scope choice matching the rest of this app (job managers are
    in-memory too) -- restarting the backend logs everyone's GitHub
    connection out, which is an acceptable trade-off here.
    """

    def __init__(self, ttl_seconds: float):
        self._ttl = ttl_seconds
        self._entries: dict[str, tuple[str, float]] = {}

    def create(self, value: str) -> str:
        key = secrets.token_urlsafe(32)
        self._entries[key] = (value, time.time() + self._ttl)
        return key

    def get(self, key: str) -> str | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.time() > expires_at:
            del self._entries[key]
            return None
        return value

    def pop(self, key: str) -> str | None:
        value = self.get(key)
        self._entries.pop(key, None)
        return value


oauth_states = _TTLStore(STATE_TTL_SECONDS)
oauth_sessions = _TTLStore(SESSION_TTL_SECONDS)
