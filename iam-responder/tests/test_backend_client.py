import httpx
import pytest

from app.backend_client import GolemBackendClient


def _client_with_transport(handler) -> GolemBackendClient:
    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    return GolemBackendClient("https://golem.example.com", "test-api-key", http_client=http_client)


def test_list_commands_calls_the_right_url_with_bearer_auth():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=[{"id": "cmd-1", "status": "role_resolved"}])

    client = _client_with_transport(handler)
    commands = client.list_commands()

    assert captured["url"] == "https://golem.example.com/api/iam-revocation/commands"
    assert captured["auth"] == "Bearer test-api-key"
    assert commands == [{"id": "cmd-1", "status": "role_resolved"}]


def test_list_commands_raises_on_a_non_2xx_response():
    client = _client_with_transport(lambda request: httpx.Response(401))
    with pytest.raises(httpx.HTTPStatusError):
        client.list_commands()


def test_report_status_posts_the_status_to_the_right_command():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = request.content
        return httpx.Response(204)

    client = _client_with_transport(handler)
    client.report_status("cmd-1", "applied")

    assert captured["url"] == "https://golem.example.com/api/iam-revocation/commands/cmd-1/status"
    assert captured["body"] == b'{"status":"applied"}'


def test_report_status_rejects_an_unknown_status():
    client = _client_with_transport(lambda request: httpx.Response(204))
    with pytest.raises(ValueError, match="Unknown status"):
        client.report_status("cmd-1", "obliterated")


def test_close_closes_the_underlying_http_client():
    client = _client_with_transport(lambda request: httpx.Response(200, json=[]))
    client.close()
    with pytest.raises(RuntimeError):
        client.list_commands()  # httpx raises once its client is closed


def test_base_url_trailing_slash_is_stripped():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json=[])

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = GolemBackendClient("https://golem.example.com/", "k", http_client=http_client)
    client.list_commands()

    assert captured["url"] == "https://golem.example.com/api/iam-revocation/commands"
