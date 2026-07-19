from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from glc.providers import BaseProvider, OpenAICompatProvider


def test_headroom_disabled_by_default(monkeypatch):
    monkeypatch.delenv("GLC_USE_HEADROOM", raising=False)
    provider = BaseProvider(api_key="mock", model="gpt-4")
    msgs = [{"role": "user", "content": "hello"}]
    res = provider._compress_messages(msgs)
    assert res == msgs

def test_headroom_enabled_graceful_fallback_if_missing(monkeypatch):
    monkeypatch.setenv("GLC_USE_HEADROOM", "true")
    # Simulate headroom missing
    with patch.dict("sys.modules", {"headroom": None}):
        provider = BaseProvider(api_key="mock", model="gpt-4")
        msgs = [{"role": "user", "content": "hello"}]
        res = provider._compress_messages(msgs)
        assert res == msgs

def test_headroom_compress_called_when_enabled(monkeypatch):
    monkeypatch.setenv("GLC_USE_HEADROOM", "true")
    monkeypatch.setenv("GLC_HEADROOM_MODEL", "compressed-gpt-4")

    mock_compress = MagicMock(return_value=[{"role": "user", "content": "compressed"}])

    # We create a dummy module for headroom
    import types
    mock_headroom = types.ModuleType("headroom")
    mock_headroom.compress = mock_compress

    with patch.dict("sys.modules", {"headroom": mock_headroom}):
        provider = BaseProvider(api_key="mock", model="gpt-4")
        msgs = [{"role": "user", "content": "hello"}]
        res = provider._compress_messages(msgs)
        assert res == [{"role": "user", "content": "compressed"}]
        mock_compress.assert_called_once_with(msgs, model="compressed-gpt-4")

@pytest.mark.asyncio
async def test_openai_compat_provider_uses_compressed_messages(monkeypatch):
    monkeypatch.setenv("GLC_USE_HEADROOM", "true")

    mock_compress = MagicMock(return_value=[{"role": "user", "content": "compressed"}])
    import types
    mock_headroom = types.ModuleType("headroom")
    mock_headroom.compress = mock_compress

    async def mock_post(*args, **kwargs):
        # Verify that the body sent contains the compressed messages
        json_body = kwargs.get("json", {})
        assert json_body["messages"] == [{"role": "user", "content": "compressed"}]
        # Return a dummy 200 response
        resp = httpx.Response(200, json={
            "choices": [{
                "message": {"role": "assistant", "content": "hello back"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10}
        })
        # Set request mock
        resp._request = httpx.Request("POST", args[0])
        return resp

    with patch.dict("sys.modules", {"headroom": mock_headroom}):
        # Mock httpx.AsyncClient.post
        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            provider = OpenAICompatProvider(api_key="mock", model="gpt-4", base_url="https://api.openai.com/v1")
            res = await provider.chat(
                messages=[{"role": "user", "content": "hello"}],
                system_blocks=[]
            )
            assert res["text"] == "hello back"
            mock_compress.assert_called_once()
