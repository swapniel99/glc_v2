"""SSRF protections for externally supplied chat image URLs."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

import httpx
import pytest
from fastapi import HTTPException

from glc import providers
from glc.routes import chat


def _image_message(url: str) -> list[dict]:
    return [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": url}}]}]


def _allow(monkeypatch, *hosts: str) -> None:
    monkeypatch.setenv("GLC_IMAGE_URL_ALLOWLIST", ",".join(hosts))


@pytest.mark.asyncio
async def test_image_fetch_fails_closed_without_allowlist(monkeypatch):
    monkeypatch.delenv("GLC_IMAGE_URL_ALLOWLIST", raising=False)

    with pytest.raises(HTTPException, match="not allowlisted"):
        await chat._resolve_image_urls(_image_message("https://1.1.1.1/image.png"))


@pytest.mark.asyncio
async def test_image_fetch_rejects_unlisted_public_host(monkeypatch):
    _allow(monkeypatch, "images.example.test")

    with pytest.raises(HTTPException, match="not allowlisted"):
        await chat._resolve_image_urls(_image_message("https://1.1.1.1/image.png"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/image.png",
        "http://10.0.0.1/image.png",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/image.png",
        "http://[fd00::1]/image.png",
        "http://[fe80::1]/image.png",
    ],
)
async def test_image_fetch_rejects_non_public_ip_addresses(url, monkeypatch):
    _allow(monkeypatch, urlsplit(url).hostname)

    with pytest.raises(HTTPException, match="public IP"):
        await chat._resolve_image_urls(_image_message(url))


@pytest.mark.asyncio
async def test_image_fetch_rejects_hostname_with_private_dns_result(monkeypatch):
    _allow(monkeypatch, "images.example.test")

    def private_dns(*args, **kwargs):
        return [(2, 1, 6, "", ("fd00::1", 0, 0, 0))]

    monkeypatch.setattr(chat.socket, "getaddrinfo", private_dns)

    with pytest.raises(HTTPException, match="public IP"):
        await chat._resolve_image_urls(_image_message("https://images.example.test/image.png"))


@pytest.mark.asyncio
async def test_image_fetch_rechecks_redirect_destination(monkeypatch):
    _allow(monkeypatch, "1.1.1.1", "127.0.0.1")

    calls = []
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://127.0.0.1/internal"}, request=request)

    def client_factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)

    with pytest.raises(HTTPException, match="public IP"):
        await chat._resolve_image_urls(_image_message("https://1.1.1.1/start"))

    assert calls == ["https://1.1.1.1/start"]


@pytest.mark.asyncio
async def test_image_fetch_allows_public_destination(monkeypatch):
    _allow(monkeypatch, "1.1.1.1")

    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "image/png"},
            content=b"image-bytes",
            request=request,
        )

    def client_factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)

    messages = await chat._resolve_image_urls(_image_message("https://1.1.1.1/image.png"))

    assert messages[0]["content"][0]["image_url"]["url"] == "data:image/png;base64,aW1hZ2UtYnl0ZXM="


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "block",
    [
        {"type": "image", "url": "https://1.1.1.1/image.png"},
        {"type": "input_image", "url": "https://1.1.1.1/image.png"},
        {
            "type": "image",
            "source": {"type": "url", "url": "https://1.1.1.1/image.png"},
        },
        {
            "type": "input_image",
            "source": {"type": "url", "url": "https://1.1.1.1/image.png"},
        },
    ],
)
async def test_alternate_image_urls_are_resolved_before_provider_payload(monkeypatch, block):
    _allow(monkeypatch, "1.1.1.1")
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "image/png"},
            content=b"image-bytes",
            request=request,
        )

    def client_factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    messages = await chat._resolve_image_urls([{"role": "user", "content": [block]}])
    payload = providers.OpenAICompatProvider("test-key", "test-model")._translate_messages(
        messages, ""
    )

    assert "https://1.1.1.1" not in json.dumps(payload)
    assert payload[0]["content"][0] == {
        "type": "image_url",
        "image_url": {"url": "data:image/png;base64,aW1hZ2UtYnl0ZXM="},
    }


@pytest.mark.asyncio
async def test_alternate_image_url_rejects_non_http_scheme():
    messages = [
        {
            "role": "user",
            "content": [{"type": "input_image", "source": {"url": "file:///etc/passwd"}}],
        }
    ]

    with pytest.raises(HTTPException, match="must use http or https"):
        await chat._resolve_image_urls(messages)


@pytest.mark.asyncio
async def test_image_fetch_allows_wildcard_subdomain(monkeypatch):
    _allow(monkeypatch, "*.example.test")

    def public_dns(*args, **kwargs):
        return [(2, 1, 6, "", ("1.1.1.1", 0))]

    monkeypatch.setattr(chat.socket, "getaddrinfo", public_dns)

    assert await chat._validate_image_url("https://cdn.example.test/image.png") == "1.1.1.1"
    with pytest.raises(HTTPException, match="not allowlisted"):
        await chat._validate_image_url("https://example.test/image.png")
