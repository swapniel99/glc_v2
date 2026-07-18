"""Short-lived credentials for channel WebSocket connections."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from glc.config import get_or_create_install_token

CHANNEL_CREDENTIAL_TTL_SECONDS = 60
MAX_CHANNEL_CREDENTIAL_TTL_SECONDS = 5 * 60
_AUDIENCE = "glc-channel-websocket"
_MAX_TOKEN_BYTES = 2_048
_CHANNEL_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class InvalidChannelCredential(Exception):
    pass


class ChannelCredentialClaims(BaseModel):
    version: Literal[1] = 1
    channel: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    audience: Literal["glc-channel-websocket"] = _AUDIENCE
    issued_at: int
    expires_at: int
    nonce: str = Field(min_length=32, max_length=128)

    model_config = ConfigDict(extra="forbid", frozen=True)


def _signing_key() -> bytes:
    install_token = get_or_create_install_token().encode()
    return hmac.new(install_token, b"glc-channel-credential-v1", hashlib.sha256).digest()


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise InvalidChannelCredential("malformed channel credential") from exc


def issue_channel_credential(
    channel: str,
    *,
    ttl_seconds: int = CHANNEL_CREDENTIAL_TTL_SECONDS,
    clock: Callable[[], float] = time.time,
) -> tuple[str, ChannelCredentialClaims]:
    if not _CHANNEL_RE.fullmatch(channel):
        raise InvalidChannelCredential("invalid channel")
    if not 1 <= ttl_seconds <= MAX_CHANNEL_CREDENTIAL_TTL_SECONDS:
        raise InvalidChannelCredential(
            f"credential TTL must be 1-{MAX_CHANNEL_CREDENTIAL_TTL_SECONDS} seconds"
        )

    now = int(clock())
    claims = ChannelCredentialClaims(
        channel=channel,
        issued_at=now,
        expires_at=now + ttl_seconds,
        nonce=secrets.token_urlsafe(32),
    )
    payload = json.dumps(
        claims.model_dump(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    encoded_payload = _b64encode(payload)
    signature = hmac.new(_signing_key(), encoded_payload.encode(), hashlib.sha256).digest()
    return f"{encoded_payload}.{_b64encode(signature)}", claims


def verify_channel_credential(
    credential: str,
    *,
    channel: str,
    clock: Callable[[], float] = time.time,
) -> ChannelCredentialClaims:
    if not isinstance(credential, str) or len(credential.encode()) > _MAX_TOKEN_BYTES:
        raise InvalidChannelCredential("malformed channel credential")
    try:
        encoded_payload, encoded_signature = credential.split(".")
    except ValueError as exc:
        raise InvalidChannelCredential("malformed channel credential") from exc

    supplied_signature = _b64decode(encoded_signature)
    expected_signature = hmac.new(
        _signing_key(),
        encoded_payload.encode(),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise InvalidChannelCredential("invalid channel credential signature")

    try:
        claims = ChannelCredentialClaims.model_validate(json.loads(_b64decode(encoded_payload)))
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError, TypeError) as exc:
        raise InvalidChannelCredential("invalid channel credential claims") from exc

    now = int(clock())
    if claims.issued_at > now or claims.expires_at <= now:
        raise InvalidChannelCredential("channel credential expired or not yet valid")
    if claims.expires_at - claims.issued_at > MAX_CHANNEL_CREDENTIAL_TTL_SECONDS:
        raise InvalidChannelCredential("channel credential lifetime exceeds limit")
    if not hmac.compare_digest(claims.channel, channel):
        raise InvalidChannelCredential("channel credential scope mismatch")
    return claims
