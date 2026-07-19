from __future__ import annotations

import base64

import httpx
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from glc.llm_schemas import MAX_CHAT_OUTPUT_TOKENS, BatchChatRequest, ChatRequest
from glc.security.endpoint_limits import EndpointRateLimiter, RequestBodyLimitMiddleware


class _DenyLimiter:
    def __init__(self) -> None:
        self.endpoints: list[str] = []

    async def acheck(self, endpoint: str) -> tuple[bool, int]:
        self.endpoints.append(endpoint)
        return False, 17


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_local_endpoint_limiter_enforces_and_expires_window():
    now = [100.0]
    limiter = EndpointRateLimiter({"chat": 2}, clock=lambda: now[0])

    assert limiter.check("chat") == (True, 0)
    assert limiter.check("chat") == (True, 0)
    assert limiter.check("chat") == (False, 60)

    now[0] = 161.0
    assert limiter.check("chat") == (True, 0)


def test_local_endpoint_limiter_enforces_daily_quota():
    limiter = EndpointRateLimiter(
        {"chat": 10},
        {"chat": 2},
        clock=lambda: 100.0,
    )

    assert limiter.check("chat") == (True, 0)
    assert limiter.check("chat") == (True, 0)
    assert limiter.check("chat") == (False, 86_400)


@pytest.mark.parametrize(
    ("path", "payload", "endpoint"),
    [
        ("/v1/chat", {"prompt": "hi"}, "chat"),
        ("/v1/chat/batch", {"calls": [{"prompt": "hi"}]}, "chat_batch"),
        (
            "/v1/vision",
            {"image": "data:image/png;base64,AA==", "prompt": "hi"},
            "vision",
        ),
        ("/v1/embed", {"text": "hi"}, "embed"),
        ("/v1/speak", {"text": "hi"}, "speak"),
        (
            "/v1/transcribe",
            {"audio_b64": base64.b64encode(b"audio").decode()},
            "transcribe",
        ),
    ],
)
def test_costly_endpoints_enforce_rate_limit(
    app_client, install_token, path, payload, endpoint
):
    limiter = _DenyLimiter()
    app_client.app.state.endpoint_rate_limiter = limiter

    response = app_client.post(path, json=payload, headers=_headers(install_token))

    assert response.status_code == 429
    assert response.json() == {"detail": "endpoint rate limit exceeded"}
    assert response.headers["retry-after"] == "17"
    assert limiter.endpoints == [endpoint]


def test_authentication_precedes_endpoint_rate_budget(app_client):
    limiter = _DenyLimiter()
    app_client.app.state.endpoint_rate_limiter = limiter

    response = app_client.post("/v1/chat", json={"prompt": "hi"})

    assert response.status_code == 401
    assert limiter.endpoints == []


def test_repeated_endpoint_calls_reach_hard_429(app_client, install_token):
    app_client.app.state.endpoint_rate_limiter = EndpointRateLimiter(
        {"chat": 1},
        {"chat": 10},
    )
    payload = {"prompt": "hi", "provider": "missing"}

    first = app_client.post("/v1/chat", json=payload, headers=_headers(install_token))
    second = app_client.post("/v1/chat", json=payload, headers=_headers(install_token))

    assert first.status_code == 400
    assert second.status_code == 429


def test_chat_and_batch_output_budgets_are_hard_limits():
    with pytest.raises(ValidationError):
        ChatRequest(prompt="hi", max_tokens=MAX_CHAT_OUTPUT_TOKENS + 1)

    with pytest.raises(ValidationError, match="batch output budget"):
        BatchChatRequest(calls=[ChatRequest(prompt="hi", max_tokens=8192) for _ in range(5)])

    with pytest.raises(ValidationError):
        BatchChatRequest(calls=[ChatRequest(prompt="hi")], max_concurrency=5)


def test_chat_input_budget_rejects_before_provider(
    app_client, install_token, monkeypatch
):
    import glc.routes.chat as chat_route

    monkeypatch.setattr(chat_route, "MAX_CHAT_INPUT_TOKENS", 1)
    response = app_client.post(
        "/v1/chat",
        json={"prompt": "12345678"},
        headers=_headers(install_token),
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "chat input exceeds 1 estimated tokens"}


def test_transcribe_decoded_audio_budget_rejects_before_provider(
    app_client, install_token, monkeypatch
):
    import glc.routes.transcribe as transcribe_route

    monkeypatch.setattr(transcribe_route, "MAX_TRANSCRIBE_AUDIO_BYTES", 3)
    response = app_client.post(
        "/v1/transcribe",
        json={"audio_b64": base64.b64encode(b"four").decode()},
        headers=_headers(install_token),
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "audio exceeds size limit"}


@pytest.mark.asyncio
async def test_remote_image_download_has_incremental_size_cap(monkeypatch):
    import glc.routes.chat as chat_route

    monkeypatch.setenv("GLC_IMAGE_URL_ALLOWLIST", "1.1.1.1")
    monkeypatch.setattr(chat_route, "MAX_IMAGE_BYTES", 3)
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"four", request=request)

    def client_factory(*args, **kwargs):
        return real_client(transport=httpx.MockTransport(handler), follow_redirects=False)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    messages = [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://1.1.1.1/a.png"}}]}]

    with pytest.raises(HTTPException) as error:
        await chat_route._resolve_image_urls(messages)

    assert error.value.status_code == 413
    assert error.value.detail == "image exceeds size limit"


@pytest.mark.asyncio
async def test_chunked_request_body_cap_rejects_before_downstream():
    downstream_called = False

    async def downstream(scope, receive, send):
        nonlocal downstream_called
        downstream_called = True

    middleware = RequestBodyLimitMiddleware(downstream, {"/v1/chat": 5})
    chunks = iter(
        [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.request", "body": b"def", "more_body": False},
        ]
    )
    sent = []

    async def receive():
        return next(chunks)

    async def send(message):
        sent.append(message)

    await middleware(
        {"type": "http", "method": "POST", "path": "/v1/chat", "headers": []},
        receive,
        send,
    )

    assert downstream_called is False
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413


def test_modal_endpoint_window_persists_across_gateway_proxies(monkeypatch):
    import modal_app

    class FakeDict:
        def __init__(self) -> None:
            self.values = {}

        def get(self, key, default=None):
            return self.values.get(key, default)

        def put(self, key, value) -> None:
            self.values[key] = value

    now = [100.0]
    shared = FakeDict()
    monkeypatch.setattr(modal_app, "endpoint_rate_windows", shared)
    monkeypatch.setattr(modal_app.time, "time", lambda: now[0])

    for _ in range(60):
        assert modal_app._run_endpoint_rate_limit("chat")["allowed"] is True
    blocked = modal_app._run_endpoint_rate_limit("chat")
    assert blocked == {"allowed": False, "retry_after": 60}

    now[0] = 161.0
    assert modal_app._run_endpoint_rate_limit("chat")["allowed"] is True
