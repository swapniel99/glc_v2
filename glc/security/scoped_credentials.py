"""One-call credentials for gateway-authorized tool actions.

Only trusted gateway code may construct ``ActionIdentity``. Adapter-supplied
identity or tenant claims must never be passed through without verification.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from glc.policy import evaluate as evaluate_policy
from glc.policy.schemas import PolicyVerdict

_SIGNING_KEY_ENV = "GLC_CAPABILITY_SIGNING_KEY"
_DEFAULT_AUDIENCE = "glc-tool-runner"
_MAX_TOKEN_BYTES = 8_192
_MAX_TTL_SECONDS = 60


class ScopedCredentialError(Exception):
    """Base error for scoped-credential failures."""


class CredentialConfigurationError(ScopedCredentialError):
    pass


class CredentialDenied(ScopedCredentialError):
    pass


class InvalidCredential(ScopedCredentialError):
    pass


class CredentialReplay(InvalidCredential):
    pass


class NonceStore(Protocol):
    async def consume(self, nonce: str, expires_at: int) -> bool:
        """Return true exactly once for a nonce."""


class MemoryNonceStore:
    """Process-local store for development and tests, not autoscaled deploys."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._used: dict[str, int] = {}
        self._lock = threading.Lock()
        self._clock = clock

    async def consume(self, nonce: str, expires_at: int) -> bool:
        now = int(self._clock())
        with self._lock:
            self._used = {key: expiry for key, expiry in self._used.items() if expiry > now}
            if nonce in self._used:
                return False
            self._used[nonce] = expires_at
            return True


class ScopedCredentialClaims(BaseModel):
    version: Literal[1] = 1
    adapter: str = Field(min_length=1, max_length=64)
    user_id: str = Field(min_length=1, max_length=512)
    tenant_id: str = Field(min_length=1, max_length=256)
    trust_level: str = Field(min_length=1, max_length=64)
    tool: str = Field(min_length=1, max_length=256)
    tool_call_id: str = Field(min_length=1, max_length=256)
    arguments_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    audience: str = Field(min_length=1, max_length=256)
    issued_at: int
    expires_at: int
    nonce: str = Field(min_length=32, max_length=128)

    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True)
class ActionIdentity:
    """Gateway-verified identity and calling component for one action."""

    adapter: str
    user_id: str
    tenant_id: str
    trust_level: str
    audience: str = _DEFAULT_AUDIENCE


def arguments_hash(arguments: dict[str, Any]) -> str:
    try:
        encoded = json.dumps(
            arguments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError) as exc:
        raise InvalidCredential("tool arguments must be canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def signing_key_from_environment() -> bytes:
    value = os.getenv(_SIGNING_KEY_ENV, "").encode()
    if len(value) < 32:
        raise CredentialConfigurationError(f"{_SIGNING_KEY_ENV} must contain at least 32 bytes")
    return value


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise InvalidCredential("malformed scoped credential") from exc


class ScopedCredentialAuthority:
    """Signs exact tool scopes and atomically consumes them at execution."""

    def __init__(
        self,
        signing_key: bytes,
        nonce_store: NonceStore,
        *,
        clock: Callable[[], float] = time.time,
        max_ttl_seconds: int = _MAX_TTL_SECONDS,
    ) -> None:
        if len(signing_key) < 32:
            raise CredentialConfigurationError("scoped credential signing key must be at least 32 bytes")
        if max_ttl_seconds < 1:
            raise CredentialConfigurationError("max TTL must be positive")
        self._signing_key = signing_key
        self._nonce_store = nonce_store
        self._clock = clock
        self._max_ttl_seconds = max_ttl_seconds

    def _issue(
        self,
        *,
        tool: str,
        tool_call_id: str,
        arguments: dict[str, Any],
        identity: ActionIdentity,
        ttl_seconds: int,
    ) -> str:
        if not 1 <= ttl_seconds <= self._max_ttl_seconds:
            raise InvalidCredential(f"credential TTL must be 1-{self._max_ttl_seconds} seconds")
        now = int(self._clock())
        try:
            claims = ScopedCredentialClaims(
                adapter=identity.adapter,
                user_id=identity.user_id,
                tenant_id=identity.tenant_id,
                trust_level=identity.trust_level,
                tool=tool,
                tool_call_id=tool_call_id,
                arguments_sha256=arguments_hash(arguments),
                audience=identity.audience,
                issued_at=now,
                expires_at=now + ttl_seconds,
                nonce=secrets.token_urlsafe(32),
            )
        except ValidationError as exc:
            raise InvalidCredential("invalid scoped credential claims") from exc
        payload = json.dumps(
            claims.model_dump(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        encoded_payload = _b64encode(payload)
        signature = hmac.new(self._signing_key, encoded_payload.encode(), hashlib.sha256).digest()
        return f"{encoded_payload}.{_b64encode(signature)}"

    async def verify_and_consume(
        self,
        credential: str,
        *,
        tool: str,
        tool_call_id: str,
        arguments: dict[str, Any],
        identity: ActionIdentity,
    ) -> ScopedCredentialClaims:
        if not isinstance(credential, str) or len(credential.encode()) > _MAX_TOKEN_BYTES:
            raise InvalidCredential("malformed scoped credential")
        try:
            encoded_payload, encoded_signature = credential.split(".")
        except ValueError as exc:
            raise InvalidCredential("malformed scoped credential") from exc

        supplied_signature = _b64decode(encoded_signature)
        expected_signature = hmac.new(
            self._signing_key,
            encoded_payload.encode(),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise InvalidCredential("invalid scoped credential signature")

        try:
            payload = json.loads(_b64decode(encoded_payload))
            claims = ScopedCredentialClaims.model_validate(payload)
        except (json.JSONDecodeError, UnicodeDecodeError, ValidationError, TypeError) as exc:
            raise InvalidCredential("invalid scoped credential claims") from exc

        now = int(self._clock())
        if claims.issued_at > now or claims.expires_at <= now:
            raise InvalidCredential("scoped credential expired or not yet valid")
        if claims.expires_at - claims.issued_at > self._max_ttl_seconds:
            raise InvalidCredential("scoped credential lifetime exceeds limit")

        expected = {
            "adapter": identity.adapter,
            "user_id": identity.user_id,
            "tenant_id": identity.tenant_id,
            "trust_level": identity.trust_level,
            "tool": tool,
            "tool_call_id": tool_call_id,
            "audience": identity.audience,
        }
        for field, value in expected.items():
            if getattr(claims, field) != value:
                raise InvalidCredential(f"scoped credential {field} mismatch")
        if not hmac.compare_digest(claims.arguments_sha256, arguments_hash(arguments)):
            raise InvalidCredential("scoped credential arguments mismatch")

        if not await self._nonce_store.consume(claims.nonce, claims.expires_at):
            raise CredentialReplay("scoped credential already consumed")
        return claims


class ScopedActionAuthorizer:
    """Policy gate that issues credentials only for final allowed arguments."""

    def __init__(
        self,
        authority: ScopedCredentialAuthority,
        *,
        policy_evaluator: Callable[[dict[str, Any], dict[str, Any]], PolicyVerdict] = evaluate_policy,
    ) -> None:
        self._authority = authority
        self._policy_evaluator = policy_evaluator

    def authorize(
        self,
        *,
        tool: str,
        tool_call_id: str,
        arguments: dict[str, Any],
        identity: ActionIdentity,
        ttl_seconds: int = 30,
    ) -> str:
        verdict = self._policy_evaluator(
            {"name": tool, "arguments": arguments},
            {
                "channel": identity.adapter,
                "channel_user_id": identity.user_id,
                "tenant_id": identity.tenant_id,
                "trust_level": identity.trust_level,
                "calling_component": identity.adapter,
            },
        )
        if verdict.action != "allow":
            raise CredentialDenied(f"tool action not authorized: {verdict.action}")
        return self._authority._issue(
            tool=tool,
            tool_call_id=tool_call_id,
            arguments=arguments,
            identity=identity,
            ttl_seconds=ttl_seconds,
        )

    async def verify_and_consume(
        self,
        credential: str,
        *,
        tool: str,
        tool_call_id: str,
        arguments: dict[str, Any],
        identity: ActionIdentity,
    ) -> ScopedCredentialClaims:
        return await self._authority.verify_and_consume(
            credential,
            tool=tool,
            tool_call_id=tool_call_id,
            arguments=arguments,
            identity=identity,
        )
