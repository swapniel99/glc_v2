from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

import pytest

from glc.channels.envelope import ChannelMessage, ChannelReply


class _FakeInput:
    def __init__(self) -> None:
        self.writes: list[str] = []

    def write(self, value: str) -> None:
        self.writes.append(value)

    def drain(self) -> None:
        return None


class _FakeSandbox:
    def __init__(self, responses: list[str] | None = None) -> None:
        self.stdin = _FakeInput()
        self.stdout = iter(responses or [])
        self.terminated = False

    def terminate(self, *, wait: bool = False) -> int:
        self.terminated = True
        return 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "expected_network", "image_name"),
    [
        ("telegram", {"outbound_domain_allowlist": ["api.telegram.org"]}, "adapter_image"),
        ("webhook", {"block_network": True}, "adapter_image"),
        ("local_mic", {"block_network": True}, "voice_adapter_image"),
    ],
)
async def test_modal_adapter_sandbox_network_is_fail_closed(monkeypatch, name, expected_network, image_name):
    import modal_app

    captured: dict[str, Any] = {}
    sandbox = _FakeSandbox()

    def fake_create(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return sandbox

    monkeypatch.setattr(modal_app.modal.Sandbox, "create", fake_create)

    session = await modal_app.ModalAdapterSession.create(name)
    await session.close()

    assert captured["args"][-1] == name
    for key, value in expected_network.items():
        assert captured["kwargs"][key] == value
    assert captured["kwargs"]["secrets"] == []
    assert "volumes" not in captured["kwargs"]
    assert captured["kwargs"]["image"] is getattr(modal_app, image_name)
    assert captured["kwargs"]["env"] == modal_app._ADAPTER_IMAGE_ENV
    assert captured["kwargs"]["workdir"] == "/tmp"
    assert captured["kwargs"]["cpu"] == (0.25, 0.5)
    assert captured["kwargs"]["memory"] == (256, 512)
    assert captured["kwargs"]["include_oidc_identity_token"] is False
    assert sandbox.terminated


def test_adapter_image_removes_shells_installers_and_code_writes():
    import modal_app

    hardening = modal_app._ADAPTER_IMAGE_HARDENING

    assert "chmod -R a-w /opt/glc /.uv/.venv" in hardening
    for path in ("/.uv/uv", "/.uv/.venv/bin/pip", "/usr/bin/apt", "/usr/bin/dpkg", "/bin/sh"):
        assert path in hardening


@pytest.mark.asyncio
async def test_modal_adapter_protocol_encodes_webhook_bytes():
    import modal_app

    message = ChannelMessage(
        channel="telegram",
        channel_user_id="owner",
        user_handle="owner",
        text="hello",
        trust_level="owner_paired",
        arrived_at=datetime.now(UTC),
    )
    response = json.dumps({"ok": True, "result": message.model_dump(mode="json")})
    sandbox = _FakeSandbox([response])
    session = modal_app.ModalAdapterSession(sandbox)  # type: ignore[arg-type]

    result = await session.on_message({"raw_body": b"payload", "headers": {"x-test": "1"}})

    assert result == message
    request = json.loads(sandbox.stdin.writes[0])
    assert base64.b64decode(request["raw"]["body_b64"]) == b"payload"
    assert request["raw"]["headers"] == {"x-test": "1"}


class _RouteSession:
    def __init__(self, channel: str) -> None:
        self.channel = channel
        self.raw: Any = None
        self.reply: ChannelReply | None = None
        self.closed = False

    async def on_message(self, raw: Any) -> ChannelMessage:
        self.raw = raw
        return ChannelMessage(
            channel=self.channel,
            channel_user_id="owner",
            user_handle="owner",
            text="hello",
            trust_level="owner_paired",
            arrived_at=datetime.now(UTC),
        )

    async def send(self, reply: ChannelReply) -> dict[str, int]:
        self.reply = reply
        return {"status": 200}

    async def close(self) -> None:
        self.closed = True


class _RouteFactory:
    def __init__(self, session: _RouteSession) -> None:
        self.session = session
        self.opened: list[str] = []

    async def open(self, name: str) -> _RouteSession:
        self.opened.append(name)
        return self.session


class _FailingFactory:
    async def open(self, name: str) -> _RouteSession:
        raise RuntimeError("secret sandbox startup detail")


def test_webhook_uses_injected_adapter_factory(app_client, monkeypatch):
    from glc.security.pairing import get_pairing_store

    get_pairing_store().force_pair_owner("whatsapp", "owner")
    session = _RouteSession("whatsapp")
    factory = _RouteFactory(session)
    monkeypatch.setattr(app_client.app.state, "adapter_session_factory", factory, raising=False)

    response = app_client.post("/v1/channels/whatsapp/webhook", content=b"payload")

    assert response.status_code == 200
    assert factory.opened == ["whatsapp"]
    assert session.raw["raw_body"] == b"payload"
    assert session.reply is not None
    assert session.reply.text == "[glc echo] hello"
    assert session.closed


def test_webhook_rejects_sandbox_channel_mismatch(app_client, monkeypatch):
    session = _RouteSession("slack")
    monkeypatch.setattr(
        app_client.app.state,
        "adapter_session_factory",
        _RouteFactory(session),
        raising=False,
    )

    response = app_client.post("/v1/channels/whatsapp/webhook", content=b"payload")

    assert response.status_code == 502
    assert response.json() == {"detail": "channel adapter returned an invalid response"}
    assert session.reply is None
    assert session.closed


def test_webhook_hides_sandbox_startup_failure(app_client, monkeypatch):
    monkeypatch.setattr(
        app_client.app.state,
        "adapter_session_factory",
        _FailingFactory(),
        raising=False,
    )

    response = app_client.post("/v1/channels/whatsapp/webhook", content=b"payload")

    assert response.status_code == 502
    assert response.json() == {"detail": "channel adapter unavailable"}
    assert "secret sandbox startup detail" not in response.text
