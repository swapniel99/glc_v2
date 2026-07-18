"""Upstream chat errors stay in server logs, not API responses."""

from __future__ import annotations

import logging

from glc.providers import ProviderError


class _FailingProvider:
    model = "test-model"
    capabilities = {}

    async def chat(self, *args, **kwargs):
        raise ProviderError("gemini HTTP 400: upstream secret detail", status=400, retryable=False)


class _FailingStreamProvider:
    model = "test-model"
    capabilities = {}

    async def stream(self, *args, **kwargs):
        if False:
            yield ""
        raise RuntimeError("upstream secret detail")


class _FallbackFailingProvider(_FailingProvider):
    async def chat(self, *args, **kwargs):
        raise ProviderError("gemini HTTP 400: upstream secret detail", status=400, retryable=True)


class _SuccessfulProvider:
    model = "test-model"
    capabilities = {}

    async def chat(self, *args, **kwargs):
        return {
            "text": "ok",
            "tool_calls": [],
            "input_tokens": 1,
            "output_tokens": 1,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "stop_reason": "end_turn",
            "model": self.model,
            "tool_call_dialect": "none",
            "reasoning_applied": False,
        }


def test_chat_hides_upstream_error_and_logs_it(app_client, install_token, caplog):
    app_client.app.state.router.providers = {"gemini": _FailingProvider()}
    app_client.app.state.router.order = ["gemini"]

    with caplog.at_level(logging.ERROR, logger="glc.routes.chat"):
        response = app_client.post(
            "/v1/chat",
            json={"prompt": "hi", "provider": "gemini"},
            headers={"Authorization": f"Bearer {install_token}"},
        )

    assert response.status_code == 502
    assert response.json() == {"detail": "Chat service temporarily unavailable"}
    assert "upstream secret detail" not in response.text
    assert "upstream secret detail" in caplog.text


def test_fallback_response_hides_prior_upstream_error(app_client, install_token, caplog):
    app_client.app.state.router.providers = {
        "gemini": _FallbackFailingProvider(),
        "groq": _SuccessfulProvider(),
    }
    app_client.app.state.router.order = ["gemini", "groq"]

    with caplog.at_level(logging.ERROR, logger="glc.routes.chat"):
        response = app_client.post(
            "/v1/chat",
            json={"prompt": "hi"},
            headers={"Authorization": f"Bearer {install_token}"},
        )

    assert response.status_code == 200
    assert response.json()["attempted"] == [{"provider": "gemini", "reason": "failed: upstream error"}]
    assert "upstream secret detail" not in response.text
    assert "upstream secret detail" in caplog.text


def test_stream_hides_upstream_error_and_logs_it(app_client, install_token, caplog):
    app_client.app.state.router.providers = {"gemini": _FailingStreamProvider()}
    app_client.app.state.router.order = ["gemini"]

    with caplog.at_level(logging.ERROR, logger="glc.routes.chat"):
        response = app_client.post(
            "/v1/chat",
            json={"prompt": "hi", "provider": "gemini", "stream": True},
            headers={"Authorization": f"Bearer {install_token}"},
        )

    assert response.status_code == 200
    assert "Chat service temporarily unavailable" in response.text
    assert "upstream secret detail" not in response.text
    assert "upstream secret detail" in caplog.text
