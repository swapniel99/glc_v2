from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest


class _FakeVolume:
    def __init__(self) -> None:
        self.reloads = 0
        self.commits = 0

    def reload(self) -> None:
        self.reloads += 1

    def commit(self) -> None:
        self.commits += 1


def test_writer_reloads_and_commits_each_operation(monkeypatch, tmp_path):
    import modal_app

    volume = _FakeVolume()
    monkeypatch.setattr(modal_app, "audit_volume", volume)
    monkeypatch.setattr(modal_app, "_AUDIT_DB_PATH", str(tmp_path / "audit.sqlite"))

    modal_app._run_audit_operation("init", {})
    row_id = modal_app._run_audit_operation(
        "append",
        {
            "channel": "telegram",
            "channel_user_id": "42",
            "trust_level": "owner_paired",
            "event_type": "inbound_message",
        },
    )
    rows = modal_app._run_audit_operation("query", {"limit": 10})
    chain_valid = modal_app._run_audit_operation("verify_chain", {})

    assert row_id == 1
    assert rows[0]["event_type"] == "inbound_message"
    assert chain_valid is True
    assert volume.reloads == 4
    assert volume.commits == 4


def test_gateway_has_no_audit_volume_mount():
    import modal_app

    assert modal_app.audit_writer.spec.volumes["/audit"].name == "glc-audit"
    assert "/audit" not in modal_app.fastapi_app.spec.volumes


def test_modal_proxy_forwards_to_remote_writer(monkeypatch):
    import modal_app

    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_remote(operation: str, payload: dict[str, Any]) -> Any:
        calls.append((operation, payload))
        return 7

    monkeypatch.setattr(modal_app.audit_writer, "remote", fake_remote)

    store = modal_app.ModalAuditStore()
    assert store.append(
        channel="x",
        channel_user_id="1",
        trust_level="owner_paired",
        event_type="boot",
    ) == 7
    assert calls == [
        (
            "append",
            {
                "channel": "x",
                "channel_user_id": "1",
                "trust_level": "owner_paired",
                "event_type": "boot",
            },
        )
    ]


@pytest.mark.asyncio
async def test_modal_proxy_uses_async_remote_writer(monkeypatch):
    import modal_app

    calls: list[tuple[str, dict[str, Any]]] = []

    async def fake_remote(operation: str, payload: dict[str, Any]) -> int:
        calls.append((operation, payload))
        return 7

    monkeypatch.setattr(modal_app.audit_writer, "remote", SimpleNamespace(aio=fake_remote))

    store = modal_app.ModalAuditStore()
    assert await store.aappend(
        channel="x",
        channel_user_id="1",
        trust_level="owner_paired",
        event_type="boot",
    ) == 7
    assert calls[0][0] == "append"


def test_modal_proxy_forwards_chain_verification(monkeypatch):
    import modal_app

    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_remote(operation: str, payload: dict[str, Any]) -> bool:
        calls.append((operation, payload))
        return True

    monkeypatch.setattr(modal_app.audit_writer, "remote", fake_remote)

    assert modal_app.ModalAuditStore().verify_chain()
    assert calls == [("verify_chain", {})]
