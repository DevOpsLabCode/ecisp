import httpx
import pytest

from app.codescan import github_oauth
from app.codescan.github_oauth import (
    OAuthError,
    OAuthNotConfigured,
    _TTLStore,
    build_authorize_url,
    exchange_code,
    is_configured,
)


@pytest.fixture(autouse=True)
def _clear_oauth_env(monkeypatch):
    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_SECRET", raising=False)


def test_is_configured_false_without_env_vars():
    assert is_configured() is False


def test_is_configured_true_with_both_env_vars(monkeypatch):
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "id")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")
    assert is_configured() is True


def test_is_configured_false_with_only_one_env_var(monkeypatch):
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "id")
    assert is_configured() is False


def test_build_authorize_url_raises_when_not_configured():
    with pytest.raises(OAuthNotConfigured):
        build_authorize_url("http://localhost:8000/callback", "state123")


def test_build_authorize_url_includes_required_params(monkeypatch):
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "my-client-id")
    url = build_authorize_url("http://localhost:8000/api/github/oauth/callback", "state123")
    assert url.startswith("https://github.com/login/oauth/authorize?")
    assert "client_id=my-client-id" in url
    assert "state=state123" in url
    assert "scope=repo" in url
    assert "redirect_uri=" in url


def test_exchange_code_raises_when_not_configured():
    with pytest.raises(OAuthNotConfigured):
        exchange_code("code123", "http://localhost:8000/callback")


def test_exchange_code_returns_access_token(monkeypatch):
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "id")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")

    def handler(request):
        assert request.url.path == "/login/oauth/access_token"
        return httpx.Response(200, json={"access_token": "gho_realtoken", "token_type": "bearer", "scope": "repo"})

    token = exchange_code("code123", "http://localhost:8000/callback", transport=httpx.MockTransport(handler))
    assert token == "gho_realtoken"


def test_exchange_code_raises_oauth_error_on_github_error_response(monkeypatch):
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "id")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")

    def handler(request):
        return httpx.Response(
            200,
            json={"error": "bad_verification_code", "error_description": "The code passed is incorrect or expired."},
        )

    with pytest.raises(OAuthError, match="incorrect or expired"):
        exchange_code("bad-code", "http://localhost:8000/callback", transport=httpx.MockTransport(handler))


def test_exchange_code_raises_when_no_access_token_in_response(monkeypatch):
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "id")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")

    def handler(request):
        return httpx.Response(200, json={"token_type": "bearer"})

    with pytest.raises(OAuthError, match="no access_token"):
        exchange_code("code123", "http://localhost:8000/callback", transport=httpx.MockTransport(handler))


def test_ttl_store_round_trips_a_value():
    store = _TTLStore(ttl_seconds=60)
    key = store.create("value1")
    assert store.get(key) == "value1"


def test_ttl_store_expires_entries(monkeypatch):
    times = [1000.0]
    monkeypatch.setattr(github_oauth.time, "time", lambda: times[0])
    store = _TTLStore(ttl_seconds=10)
    key = store.create("value1")
    times[0] = 1011.0  # past the 10s ttl
    assert store.get(key) is None


def test_ttl_store_pop_removes_the_entry():
    store = _TTLStore(ttl_seconds=60)
    key = store.create("value1")
    assert store.pop(key) == "value1"
    assert store.get(key) is None


def test_ttl_store_get_and_pop_return_none_for_unknown_key():
    store = _TTLStore(ttl_seconds=60)
    assert store.get("nope") is None
    assert store.pop("nope") is None


def test_module_level_stores_exist_and_are_independent():
    state = github_oauth.oauth_states.create("s")
    session = github_oauth.oauth_sessions.create("t")
    assert github_oauth.oauth_states.get(state) == "s"
    assert github_oauth.oauth_sessions.get(session) == "t"
    assert github_oauth.oauth_states.get(session) is None
