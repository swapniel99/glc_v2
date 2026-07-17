"""SSRF protections for externally supplied chat image URLs."""

from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException

from glc.routes import chat


def _image_message(url: str) -> list[dict]:
    return [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": url}}]}]


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
async def test_image_fetch_rejects_non_public_ip_addresses(url):
    with pytest.raises(HTTPException, match="public IP"):
        await chat._resolve_image_urls(_image_message(url))


@pytest.mark.asyncio
async def test_image_fetch_rejects_hostname_with_private_dns_result(monkeypatch):
    def private_dns(*args, **kwargs):
        return [(2, 1, 6, "", ("fd00::1", 0, 0, 0))]

    monkeypatch.setattr(chat.socket, "getaddrinfo", private_dns)

    with pytest.raises(HTTPException, match="public IP"):
        await chat._resolve_image_urls(_image_message("https://images.example.test/image.png"))


@pytest.mark.asyncio
async def test_image_fetch_rechecks_redirect_destination(monkeypatch):
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
