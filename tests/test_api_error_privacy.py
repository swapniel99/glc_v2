"""External-service failure details stay in server logs."""

from __future__ import annotations

import base64
import logging

import httpx
import pytest
from fastapi import HTTPException

from glc import db
from glc.embedders import EmbedderError, EmbedRateState
from glc.routes import chat as chat_route
from glc.voice.stt import STTError
from glc.voice.stt.base import STTProvider
from glc.voice.stt.router import register_test_provider as register_stt_provider
from glc.voice.tts import TTSError
from glc.voice.tts.base import TTSProvider
from glc.voice.tts.router import register_test_provider as register_tts_provider


class _FailingEmbedder:
    name = "gemini"
    model = "embed-test"

    def __init__(self):
        self.state = EmbedRateState(rpm=0, cooldown=0)

    async def embed(self, *args, **kwargs):
        raise EmbedderError("gemini HTTP 400: upstream secret detail", status=400)


class _FailingTTS(TTSProvider):
    name = "kokoro"

    async def synthesize(self, *args, **kwargs):
        raise TTSError("TTS upstream secret detail", status=502)


class _SuccessfulEmbedder:
    name = "ollama"
    model = "embed-test"

    def __init__(self):
        self.state = EmbedRateState(rpm=0, cooldown=0)

    async def embed(self, *args, **kwargs):
        return {"embedding": [1.0], "model": self.model, "dim": 1}


class _FailingSTT(STTProvider):
    name = "groq_whisper"

    async def transcribe(self, *args, **kwargs):
        raise STTError("STT upstream secret detail", status=502)


def test_embed_hides_upstream_error_and_redacts_status(app_client, install_token, caplog):
    app_client.app.state.embedders = [_FailingEmbedder()]
    app_client.app.state.embed_order = ["gemini"]
    headers = {"Authorization": f"Bearer {install_token}"}

    with caplog.at_level(logging.ERROR):
        response = app_client.post("/v1/embed", json={"text": "hi"}, headers=headers)

    assert response.status_code == 503
    assert response.json() == {"detail": "Embedding service temporarily unavailable"}
    assert "upstream secret detail" not in response.text
    assert "upstream secret detail" in caplog.text

    status = app_client.get("/v1/embedders", headers=headers).json()
    assert status["live"]["gemini"]["backoff_reason"] == "unavailable"


def test_embed_fallback_hides_prior_upstream_error(app_client, install_token, caplog):
    app_client.app.state.embedders = [_FailingEmbedder(), _SuccessfulEmbedder()]

    with caplog.at_level(logging.ERROR, logger="glc.embedders"):
        response = app_client.post(
            "/v1/embed",
            json={"text": "hi"},
            headers={"Authorization": f"Bearer {install_token}"},
        )

    assert response.status_code == 200
    assert response.json()["attempted"] == [{"provider": "gemini", "reason": "unavailable"}]
    assert "upstream secret detail" not in response.text
    assert "upstream secret detail" in caplog.text


def test_speak_hides_upstream_error_and_logs_it(app_client, install_token, caplog):
    register_tts_provider("kokoro", _FailingTTS())
    try:
        with caplog.at_level(logging.ERROR, logger="glc.routes.speak"):
            response = app_client.post(
                "/v1/speak",
                json={"text": "hi"},
                headers={"Authorization": f"Bearer {install_token}"},
            )
    finally:
        register_tts_provider("kokoro", None)

    assert response.status_code == 502
    assert response.json() == {"detail": "Speech synthesis service temporarily unavailable"}
    assert "upstream secret detail" not in response.text
    assert "upstream secret detail" in caplog.text


def test_transcribe_hides_upstream_error_and_logs_it(app_client, install_token, caplog):
    register_stt_provider("groq_whisper", _FailingSTT())
    try:
        with caplog.at_level(logging.ERROR, logger="glc.routes.transcribe"):
            response = app_client.post(
                "/v1/transcribe",
                json={"audio_b64": base64.b64encode(b"audio").decode()},
                headers={"Authorization": f"Bearer {install_token}"},
            )
    finally:
        register_stt_provider("groq_whisper", None)

    assert response.status_code == 502
    assert response.json() == {"detail": "Transcription service temporarily unavailable"}
    assert "upstream secret detail" not in response.text
    assert "upstream secret detail" in caplog.text


def test_calls_redacts_stored_failure_detail(app_client, install_token):
    db.log_call(
        provider="gemini",
        model="test",
        status="error",
        error="upstream secret detail",
        attempted="raw attempt",
    )

    response = app_client.get("/v1/calls", headers={"Authorization": f"Bearer {install_token}"})

    assert response.status_code == 200
    assert response.json()[0]["error"] == "Service failure"
    assert response.json()[0]["attempted"] == "Redacted"
    assert "upstream secret detail" not in response.text


def test_batch_hides_unexpected_error(app_client, install_token, caplog, monkeypatch):
    async def fail(*args, **kwargs):
        raise RuntimeError("upstream secret detail")

    monkeypatch.setattr(chat_route, "chat", fail)
    with caplog.at_level(logging.ERROR, logger="glc.routes.chat"):
        response = app_client.post(
            "/v1/chat/batch",
            json={"calls": [{"prompt": "hi"}]},
            headers={"Authorization": f"Bearer {install_token}"},
        )

    assert response.status_code == 200
    assert response.json() == {
        "results": [{"error": "Chat service temporarily unavailable", "status_code": 500}]
    }
    assert "upstream secret detail" not in response.text
    assert "upstream secret detail" in caplog.text


@pytest.mark.asyncio
async def test_image_fetch_hides_upstream_error(monkeypatch, caplog):
    monkeypatch.setenv("GLC_IMAGE_URL_ALLOWLIST", "1.1.1.1")
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, content=b"upstream secret detail", request=request)

    def client_factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    messages = [
        {
            "role": "user",
            "content": [{"type": "image_url", "image_url": {"url": "https://1.1.1.1/image.png"}}],
        }
    ]

    with caplog.at_level(logging.ERROR, logger="glc.routes.chat"):
        with pytest.raises(HTTPException) as error:
            await chat_route._resolve_image_urls(messages)

    assert error.value.status_code == 502
    assert error.value.detail == "Image retrieval failed"
    assert "upstream secret detail" not in str(error.value.detail)
