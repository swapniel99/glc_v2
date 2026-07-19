"""Credential-bearing adapter requests stay inside provider boundaries."""

from __future__ import annotations

import httpx
import pytest

from glc.channels.catalogue.teams import adapter as teams
from glc.channels.catalogue.twilio_sms import adapter as twilio_sms
from glc.channels.envelope import ChannelReply
from glc.security.outbound_urls import UnsafeOutboundURL, validate_provider_url


@pytest.mark.parametrize(
    "url",
    [
        "http://api.twilio.com/media",
        "https://attacker.example/media",
        "https://api.twilio.com@attacker.example/media",
        "https://api.twilio.com:8443/media",
        "https://127.0.0.1/media",
    ],
)
def test_provider_url_rejects_untrusted_origins(url):
    with pytest.raises(UnsafeOutboundURL):
        validate_provider_url(url, allowed_hosts=("api.twilio.com",))


def test_provider_url_wildcard_requires_subdomain_boundary():
    assert (
        validate_provider_url(
            "https://connector.botframework.com/v3/messages",
            allowed_hosts=("*.botframework.com",),
        )
        == "https://connector.botframework.com/v3/messages"
    )
    with pytest.raises(UnsafeOutboundURL):
        validate_provider_url(
            "https://evilbotframework.com/v3/messages",
            allowed_hosts=("*.botframework.com",),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "service_url",
    [
        "https://attacker.example",
        "https://evil.trafficmanager.net",
        "http://127.0.0.1",
    ],
)
async def test_teams_rejects_untrusted_service_url_before_caching(service_url):
    adapter = teams.Adapter()
    activity = {
        "type": "message",
        "id": "activity",
        "from": {"id": "user"},
        "conversation": {"id": "conversation"},
        "serviceUrl": service_url,
    }

    with pytest.raises(UnsafeOutboundURL):
        await adapter.on_message(activity)
    assert adapter._conv_cache == {}


@pytest.mark.asyncio
async def test_teams_revalidates_before_fetching_token(monkeypatch):
    adapter = teams.Adapter()
    adapter._conv_cache["user"] = {
        "service_url": "http://127.0.0.1",
        "conversation_id": "conversation",
    }
    token_requested = False

    async def fake_fetch_token():
        nonlocal token_requested
        token_requested = True
        return "secret-token"

    monkeypatch.setattr(teams, "_fetch_token", fake_fetch_token)

    with pytest.raises(UnsafeOutboundURL):
        await adapter.send(ChannelReply(channel="teams", channel_user_id="user", text="reply"))
    assert token_requested is False


@pytest.mark.asyncio
async def test_teams_rejects_service_redirect(monkeypatch):
    real_client = httpx.AsyncClient
    calls: list[str] = []

    async def fake_fetch_token():
        return "secret-token"

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(
            302,
            headers={"location": "https://attacker.example/steal"},
            request=request,
        )

    def client_factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(**kwargs)

    monkeypatch.setattr(teams, "_fetch_token", fake_fetch_token)
    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    adapter = teams.Adapter()
    adapter._conv_cache["user"] = {
        "service_url": "https://smba.trafficmanager.net/amer/",
        "conversation_id": "conversation",
    }

    with pytest.raises(RuntimeError, match="redirected"):
        await adapter.send(ChannelReply(channel="teams", channel_user_id="user", text="reply"))
    assert calls == [
        "https://smba.trafficmanager.net/amer/v3/conversations/conversation/activities/"
    ]


@pytest.mark.asyncio
async def test_twilio_rejects_untrusted_media_before_http_client(monkeypatch):
    def forbidden_client(*args, **kwargs):
        raise AssertionError("HTTP client must not be created")

    monkeypatch.setattr(httpx, "AsyncClient", forbidden_client)

    with pytest.raises(UnsafeOutboundURL):
        await twilio_sms.Adapter()._download_media("https://attacker.example/media")


@pytest.mark.asyncio
async def test_twilio_downloads_allowed_media_without_redirects(monkeypatch):
    real_client = httpx.AsyncClient
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        assert request.headers["authorization"].startswith("Basic ")
        return httpx.Response(200, content=b"media", request=request)

    def client_factory(**kwargs):
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC-test")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "token")

    data = await twilio_sms.Adapter()._download_media("https://api.twilio.com/media?id=1")
    assert data == b"media"
    assert calls == ["https://api.twilio.com/media?id=1"]


@pytest.mark.asyncio
async def test_twilio_rejects_media_redirect(monkeypatch):
    real_client = httpx.AsyncClient
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(
            302,
            headers={"location": "https://attacker.example/steal"},
            request=request,
        )

    def client_factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)

    with pytest.raises(UnsafeOutboundURL, match="redirected"):
        await twilio_sms.Adapter()._download_media("https://api.twilio.com/media")
    assert calls == ["https://api.twilio.com/media"]


@pytest.mark.asyncio
async def test_twilio_rejects_oversized_media(monkeypatch):
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": str(twilio_sms._MAX_MEDIA_BYTES + 1)},
            request=request,
        )

    def client_factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)

    with pytest.raises(ValueError, match="size limit"):
        await twilio_sms.Adapter()._download_media("https://api.twilio.com/media")
