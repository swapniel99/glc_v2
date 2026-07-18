from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from glc.security.scoped_credentials import (
    ActionIdentity,
    CredentialDenied,
    InvalidCredential,
)

_IDENTITY = ActionIdentity(
    adapter="whatsapp",
    user_id="owner-1",
    tenant_id="tenant-a",
    trust_level="owner_paired",
)


def _payload(*, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": tool,
        "tool_call_id": "call-1",
        "arguments": arguments,
        "identity": {
            "adapter": _IDENTITY.adapter,
            "user_id": _IDENTITY.user_id,
            "tenant_id": _IDENTITY.tenant_id,
            "trust_level": _IDENTITY.trust_level,
            "audience": _IDENTITY.audience,
        },
        "ttl_seconds": 30,
    }


def test_policy_service_alone_holds_capability_secret_and_no_volume():
    import modal_app

    policy_secret_names = [secret.name for secret in modal_app.policy_credential_service.spec.secrets]
    gateway_secret_names = [secret.name for secret in modal_app.fastapi_app.spec.secrets]

    assert policy_secret_names == ["glc-capability-signing-key"]
    assert modal_app.policy_credential_service.spec.volumes == {}
    assert gateway_secret_names == ["glc-llm-keys"]
    assert "glc-capability-signing-key" not in gateway_secret_names


def test_policy_service_denies_without_issuing_credential(monkeypatch):
    import modal_app

    monkeypatch.setenv("GLC_CAPABILITY_SIGNING_KEY", "k" * 32)

    with pytest.raises(CredentialDenied, match="deny"):
        modal_app._run_policy_credential_operation(
            "authorize",
            _payload(tool="file.delete", arguments={"path": "~/Documents/private.txt"}),
        )


def test_policy_service_issues_and_redeems_exact_allowed_action(monkeypatch):
    import modal_app

    class _Put:
        async def aio(self, *args, **kwargs):
            return True

    monkeypatch.setenv("GLC_CAPABILITY_SIGNING_KEY", "k" * 32)
    monkeypatch.setattr(modal_app, "capability_nonces", SimpleNamespace(put=_Put()))
    authorize_payload = _payload(tool="calendar.create", arguments={"title": "review"})
    credential = modal_app._run_policy_credential_operation("authorize", authorize_payload)
    verify_payload = {key: value for key, value in authorize_payload.items() if key != "ttl_seconds"}
    verify_payload["credential"] = credential

    claims = modal_app._run_policy_credential_operation("verify", verify_payload)

    assert claims["tool"] == "calendar.create"
    assert claims["arguments_sha256"]


def test_policy_service_rejects_unexpected_request_fields(monkeypatch):
    import modal_app

    monkeypatch.setenv("GLC_CAPABILITY_SIGNING_KEY", "k" * 32)
    payload = _payload(tool="calendar.create", arguments={})
    payload["action"] = "allow"

    with pytest.raises(ValueError, match="invalid policy request"):
        modal_app._run_policy_credential_operation("authorize", payload)


def test_gateway_proxy_forwards_final_action_to_policy_service(monkeypatch):
    import modal_app

    captured: dict[str, Any] = {}

    def remote(operation: str, payload: dict[str, Any]) -> str:
        captured.update({"operation": operation, "payload": payload})
        return "signed-credential"

    monkeypatch.setattr(modal_app.policy_credential_service, "remote", remote)

    credential = modal_app.ModalPolicyAuthorizer().authorize(
        tool="calendar.create",
        tool_call_id="call-1",
        arguments={"title": "review"},
        identity=_IDENTITY,
        ttl_seconds=12,
    )

    assert credential == "signed-credential"
    assert captured == {
        "operation": "authorize",
        "payload": _payload(tool="calendar.create", arguments={"title": "review"}) | {"ttl_seconds": 12},
    }


def test_gateway_proxy_fails_closed_when_policy_service_fails(monkeypatch):
    import modal_app

    def remote(operation: str, payload: dict[str, Any]) -> str:
        raise RuntimeError("unavailable")

    monkeypatch.setattr(modal_app.policy_credential_service, "remote", remote)

    with pytest.raises(CredentialDenied, match="policy authorization failed"):
        modal_app.ModalPolicyAuthorizer().authorize(
            tool="calendar.create",
            tool_call_id="call-1",
            arguments={},
            identity=_IDENTITY,
        )


@pytest.mark.asyncio
async def test_gateway_proxy_fails_closed_when_remote_verification_fails(monkeypatch):
    import modal_app

    def remote(operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("unavailable")

    monkeypatch.setattr(modal_app.policy_credential_service, "remote", remote)

    with pytest.raises(InvalidCredential, match="policy credential verification failed"):
        await modal_app.ModalPolicyAuthorizer().verify_and_consume(
            "credential",
            tool="calendar.create",
            tool_call_id="call-1",
            arguments={},
            identity=_IDENTITY,
        )
