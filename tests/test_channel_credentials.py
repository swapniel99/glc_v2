from __future__ import annotations

from datetime import UTC, datetime

import pytest
from starlette.websockets import WebSocketDisconnect

from glc.channels.envelope import ChannelMessage
from glc.security.channel_credentials import (
    InvalidChannelCredential,
    issue_channel_credential,
    verify_channel_credential,
)


def test_channel_credential_is_bound_to_channel_and_expiry():
    credential, claims = issue_channel_credential("telegram", ttl_seconds=60, clock=lambda: 1_000)

    assert verify_channel_credential(
        credential,
        channel="telegram",
        clock=lambda: 1_059,
    ) == claims
    with pytest.raises(InvalidChannelCredential, match="scope mismatch"):
        verify_channel_credential(credential, channel="discord", clock=lambda: 1_059)
    with pytest.raises(InvalidChannelCredential, match="expired"):
        verify_channel_credential(credential, channel="telegram", clock=lambda: 1_060)


def test_channel_credential_rejects_tampering_and_excessive_ttl():
    credential, _ = issue_channel_credential("telegram")
    payload, signature = credential.split(".")
    replacement = "A" if signature[0] != "A" else "B"

    with pytest.raises(InvalidChannelCredential, match="signature"):
        verify_channel_credential(f"{payload}.{replacement}{signature[1:]}", channel="telegram")
    with pytest.raises(InvalidChannelCredential, match="TTL"):
        issue_channel_credential("telegram", ttl_seconds=301)


def _mint(app_client, install_token: str, channel: str = "telegram", ttl_seconds: int = 60) -> str:
    response = app_client.post(
        f"/v1/control/channels/{channel}/credential",
        headers={"Authorization": f"Bearer {install_token}"},
        json={"ttl_seconds": ttl_seconds},
    )
    assert response.status_code == 200
    return response.json()["credential"]


def test_channel_credential_endpoint_requires_install_token(app_client):
    response = app_client.post(
        "/v1/control/channels/telegram/credential",
        json={"ttl_seconds": 60},
    )

    assert response.status_code == 401


@pytest.mark.parametrize("auth_kind", ["missing", "install_token", "query_credential", "wrong_channel"])
def test_channel_websocket_rejects_unscoped_auth(app_client, install_token, auth_kind):
    credential = _mint(app_client, install_token)
    path = "/v1/channels/telegram"
    headers = {}
    if auth_kind == "install_token":
        headers = {"Authorization": f"Bearer {install_token}"}
    elif auth_kind == "query_credential":
        path += f"?token={credential}"
    elif auth_kind == "wrong_channel":
        credential = _mint(app_client, install_token, "discord")
        headers = {"Authorization": f"Bearer {credential}"}

    with pytest.raises(WebSocketDisconnect) as exc_info:
        with app_client.websocket_connect(path, headers=headers):
            pass

    assert exc_info.value.code == 1008


def test_channel_websocket_accepts_scoped_credential(app_client, install_token):
    from glc.security.pairing import get_pairing_store

    get_pairing_store().force_pair_owner("whatsapp", "owner")
    credential = _mint(app_client, install_token, "whatsapp")
    message = ChannelMessage(
        channel="whatsapp",
        channel_user_id="owner",
        user_handle="owner",
        text="hello",
        trust_level="owner_paired",
        arrived_at=datetime.now(UTC),
    )

    with app_client.websocket_connect(
        "/v1/channels/whatsapp",
        headers={"Authorization": f"Bearer {credential}"},
    ) as websocket:
        websocket.send_text(message.model_dump_json())
        response = websocket.receive_json()

    assert response["channel"] == "whatsapp"
    assert response["text"] == "[glc echo] hello"


def test_channel_websocket_rejects_cross_channel_envelope(app_client, install_token):
    credential = _mint(app_client, install_token, "whatsapp")
    message = ChannelMessage(
        channel="discord",
        channel_user_id="owner",
        user_handle="owner",
        text="hello",
        trust_level="owner_paired",
        arrived_at=datetime.now(UTC),
    )

    with app_client.websocket_connect(
        "/v1/channels/whatsapp",
        headers={"Authorization": f"Bearer {credential}"},
    ) as websocket:
        websocket.send_text(message.model_dump_json())
        response = websocket.receive_json()

    assert response == {"error": "channel does not match route"}


def test_channel_websocket_closes_when_credential_expires(app_client, install_token):
    credential = _mint(app_client, install_token, "whatsapp", ttl_seconds=1)

    with app_client.websocket_connect(
        "/v1/channels/whatsapp",
        headers={"Authorization": f"Bearer {credential}"},
    ) as websocket:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            websocket.receive_json()

    assert exc_info.value.code == 1008
