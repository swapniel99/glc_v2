from __future__ import annotations

import asyncio
import base64
import json
from types import SimpleNamespace
from typing import Any

import pytest

from glc.policy.schemas import PolicyVerdict
from glc.security.scoped_credentials import (
    ActionIdentity,
    CredentialConfigurationError,
    CredentialDenied,
    CredentialReplay,
    InvalidCredential,
    MemoryNonceStore,
    ScopedActionAuthorizer,
    ScopedCredentialAuthority,
    signing_key_from_environment,
)

_KEY = b"k" * 32
_IDENTITY = ActionIdentity(
    adapter="whatsapp",
    user_id="user-123",
    tenant_id="tenant-a",
    trust_level="owner_paired",
)
_ARGUMENTS = {"recipient": "person@example.test", "subject": "hello"}


def _verdict(action: str = "allow") -> PolicyVerdict:
    return PolicyVerdict(action=action, reason="test")  # type: ignore[arg-type]


def _authorizer(clock=lambda: 1_000.0, evaluator=lambda tool, context: _verdict()):
    authority = ScopedCredentialAuthority(_KEY, MemoryNonceStore(clock=clock), clock=clock)
    return ScopedActionAuthorizer(authority, policy_evaluator=evaluator)


def _issue(authorizer: ScopedActionAuthorizer) -> str:
    return authorizer.authorize(
        tool="email.send",
        tool_call_id="call-1",
        arguments=_ARGUMENTS,
        identity=_IDENTITY,
    )


@pytest.mark.asyncio
async def test_scoped_credential_binds_every_action_dimension_and_is_one_time():
    authorizer = _authorizer()
    credential = _issue(authorizer)

    claims = await authorizer.verify_and_consume(
        credential,
        tool="email.send",
        tool_call_id="call-1",
        arguments={"subject": "hello", "recipient": "person@example.test"},
        identity=_IDENTITY,
    )

    assert claims.adapter == "whatsapp"
    assert claims.user_id == "user-123"
    assert claims.tenant_id == "tenant-a"
    assert claims.audience == "glc-tool-runner"
    with pytest.raises(CredentialReplay):
        await authorizer.verify_and_consume(
            credential,
            tool="email.send",
            tool_call_id="call-1",
            arguments=_ARGUMENTS,
            identity=_IDENTITY,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("overrides", "identity"),
    [
        ({"tool": "files.delete"}, _IDENTITY),
        ({"tool_call_id": "call-2"}, _IDENTITY),
        ({"arguments": {"recipient": "attacker@example.test", "subject": "hello"}}, _IDENTITY),
        ({}, ActionIdentity("slack", "user-123", "tenant-a", "owner_paired")),
        ({}, ActionIdentity("whatsapp", "user-456", "tenant-a", "owner_paired")),
        ({}, ActionIdentity("whatsapp", "user-123", "tenant-b", "owner_paired")),
        ({}, ActionIdentity("whatsapp", "user-123", "tenant-a", "untrusted")),
        (
            {},
            ActionIdentity(
                "whatsapp",
                "user-123",
                "tenant-a",
                "owner_paired",
                audience="other-runner",
            ),
        ),
    ],
)
async def test_scope_mismatch_rejected_without_consuming_valid_credential(overrides, identity):
    authorizer = _authorizer()
    credential = _issue(authorizer)
    supplied: dict[str, Any] = {
        "tool": "email.send",
        "tool_call_id": "call-1",
        "arguments": _ARGUMENTS,
        "identity": identity,
    }
    supplied.update(overrides)

    with pytest.raises(InvalidCredential):
        await authorizer.verify_and_consume(credential, **supplied)

    await authorizer.verify_and_consume(
        credential,
        tool="email.send",
        tool_call_id="call-1",
        arguments=_ARGUMENTS,
        identity=_IDENTITY,
    )


@pytest.mark.asyncio
async def test_expired_and_tampered_credentials_rejected():
    now = [1_000.0]
    authorizer = _authorizer(clock=lambda: now[0])
    credential = _issue(authorizer)
    payload, signature = credential.split(".")
    tampered = ("A" if payload[0] != "A" else "B") + payload[1:] + "." + signature

    with pytest.raises(InvalidCredential, match="signature"):
        await authorizer.verify_and_consume(
            tampered,
            tool="email.send",
            tool_call_id="call-1",
            arguments=_ARGUMENTS,
            identity=_IDENTITY,
        )

    now[0] = 1_030.0
    with pytest.raises(InvalidCredential, match="expired"):
        await authorizer.verify_and_consume(
            credential,
            tool="email.send",
            tool_call_id="call-1",
            arguments=_ARGUMENTS,
            identity=_IDENTITY,
        )


def test_policy_checks_final_arguments_and_verified_identity_before_issuance():
    seen: dict[str, Any] = {}

    def evaluate(tool_call, context):
        seen["tool_call"] = tool_call
        seen["context"] = context
        return _verdict()

    credential = _issue(_authorizer(evaluator=evaluate))

    assert credential
    assert seen["tool_call"] == {"name": "email.send", "arguments": _ARGUMENTS}
    assert seen["context"] == {
        "channel": "whatsapp",
        "channel_user_id": "user-123",
        "tenant_id": "tenant-a",
        "trust_level": "owner_paired",
        "calling_component": "whatsapp",
    }


@pytest.mark.parametrize("action", ["deny", "require_approval"])
def test_non_allow_policy_verdict_never_issues_credential(action):
    authorizer = _authorizer(evaluator=lambda tool, context: _verdict(action))

    with pytest.raises(CredentialDenied, match=action):
        _issue(authorizer)


def test_credential_contains_argument_hash_not_argument_values():
    credential = _issue(_authorizer())
    encoded_payload = credential.split(".")[0]
    payload = base64.urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4))

    assert "person@example.test" not in payload.decode()
    assert json.loads(payload)["arguments_sha256"]


def test_signing_key_is_required_and_never_weak(monkeypatch):
    monkeypatch.delenv("GLC_CAPABILITY_SIGNING_KEY", raising=False)
    with pytest.raises(CredentialConfigurationError):
        signing_key_from_environment()

    monkeypatch.setenv("GLC_CAPABILITY_SIGNING_KEY", "short")
    with pytest.raises(CredentialConfigurationError):
        signing_key_from_environment()


@pytest.mark.asyncio
async def test_only_one_concurrent_redemption_succeeds():
    authorizer = _authorizer()
    credential = _issue(authorizer)

    async def redeem() -> str:
        try:
            await authorizer.verify_and_consume(
                credential,
                tool="email.send",
                tool_call_id="call-1",
                arguments=_ARGUMENTS,
                identity=_IDENTITY,
            )
            return "ok"
        except CredentialReplay:
            return "replay"

    assert sorted(await asyncio.gather(redeem(), redeem())) == ["ok", "replay"]


@pytest.mark.asyncio
async def test_modal_nonce_store_uses_atomic_put_if_absent(monkeypatch):
    import modal_app

    captured: dict[str, Any] = {}

    class _Put:
        async def aio(self, *args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return True

    monkeypatch.setattr(modal_app, "capability_nonces", SimpleNamespace(put=_Put()))

    assert await modal_app.ModalNonceStore().consume("nonce", 1234)
    assert captured == {
        "args": ("nonce", 1234),
        "kwargs": {"skip_if_exists": True},
    }


def test_adapter_secret_mapping_rejects_gateway_or_cross_adapter_secret(monkeypatch):
    import modal_app

    for secret_name in ("glc-llm-keys", "glc-capability-signing-key", "glc-adapter-slack"):
        monkeypatch.setenv(
            "GLC_MODAL_ADAPTER_SECRETS_JSON",
            json.dumps({"telegram": secret_name}),
        )
        with pytest.raises(ValueError, match="glc-adapter-telegram"):
            modal_app._load_adapter_secrets()


def test_adapter_secret_mapping_accepts_only_own_named_secret(monkeypatch):
    import modal_app

    sentinel = object()
    monkeypatch.setenv(
        "GLC_MODAL_ADAPTER_SECRETS_JSON",
        json.dumps({"twilio_sms": "glc-adapter-twilio-sms"}),
    )
    monkeypatch.setattr(modal_app.modal.Secret, "from_name", lambda name: sentinel)

    assert modal_app._load_adapter_secrets() == {"twilio_sms": sentinel}


@pytest.mark.asyncio
async def test_production_cannot_fall_back_to_in_process_adapter(monkeypatch):
    from glc.channels.execution import open_adapter_session

    monkeypatch.setenv("GLC_ENV", "production")
    with pytest.raises(RuntimeError, match="sandbox adapter factory required"):
        await open_adapter_session(SimpleNamespace(), "whatsapp")
