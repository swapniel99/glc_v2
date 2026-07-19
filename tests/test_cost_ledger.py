from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from glc import db
from glc.routing import Router


class _FakeVolume:
    def __init__(self) -> None:
        self.reloads = 0
        self.commits = 0

    def reload(self) -> None:
        self.reloads += 1

    def commit(self) -> None:
        self.commits += 1


@pytest.fixture(autouse=True)
def _local_signed_ledger():
    previous = db.get_ledger()
    db.configure_ledger(db.LocalSignedCostLedger(key=b"l" * 32))
    yield
    db.configure_ledger(previous)


@pytest.mark.parametrize(
    "bad_value",
    [-1, db._MAX_TOKENS_PER_CALL + 1, True, "100"],
)
def test_writer_rejects_invalid_token_counts(bad_value):
    db.init()

    with pytest.raises(db.InvalidCostRecord, match="input_tokens"):
        db.log_call(provider="test", model="test-model", input_tokens=bad_value)

    assert db.recent() == []


def test_writer_rejects_arbitrary_status():
    db.init()

    with pytest.raises(db.InvalidCostRecord, match="status"):
        db.log_call(provider="test", model="test-model", status="forged")

    assert db.recent() == []


def test_signed_append_rejects_tampering_and_replay():
    key = b"s" * 32
    db._sqlite_init()
    record = db.build_record(provider="test", model="test-model", input_tokens=12)
    signature = db.sign_record(record, key)

    tampered = {**record, "input_tokens": 13}
    with pytest.raises(db.InvalidCostRecord, match="signature"):
        db.append_signed(tampered, signature, key)

    db.append_signed(record, signature, key)
    with pytest.raises(db.InvalidCostRecord, match="replayed"):
        db.append_signed(record, signature, key)

    assert db.aggregate()["test"]["in_tok"] == 12


def test_recent_does_not_expose_writer_proof():
    db.init()
    db.log_call(provider="test", model="test-model", input_tokens=12, output_tokens=3)

    row = db.recent()[0]

    assert row["input_tokens"] == 12
    assert "writer_nonce" not in row
    assert "writer_signature" not in row


def test_existing_cost_database_migrates_to_signed_records():
    with db.conn() as connection:
        connection.execute(
            """CREATE TABLE calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
                provider TEXT NOT NULL, model TEXT NOT NULL,
                input_tokens INTEGER DEFAULT 0, output_tokens INTEGER DEFAULT 0,
                cache_create_tokens INTEGER DEFAULT 0, cache_read_tokens INTEGER DEFAULT 0,
                latency_ms INTEGER DEFAULT 0, status TEXT, error TEXT,
                prompt_chars INTEGER DEFAULT 0, response_chars INTEGER DEFAULT 0,
                override TEXT, attempted TEXT, tool_calls INTEGER DEFAULT 0,
                reasoning_applied INTEGER DEFAULT 0, tool_dialect TEXT,
                call_role TEXT DEFAULT 'worker', router_decision TEXT,
                embed_dim INTEGER, agent TEXT, session TEXT, retries INTEGER DEFAULT 0
            )"""
        )

    db.init()
    db.log_call(provider="test", model="test-model", input_tokens=5)

    with db.conn() as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(calls)")}
        proof = connection.execute(
            "SELECT writer_nonce, writer_signature FROM calls"
        ).fetchone()
    assert {"writer_nonce", "writer_signature"} <= columns
    assert len(proof["writer_nonce"]) == 32
    assert len(proof["writer_signature"]) == 64


def test_provider_cannot_poison_ledger_or_budget_with_usage(app_client, install_token):
    class _PoisonedProvider:
        model = "poisoned-model"
        capabilities: dict[str, bool] = {}

        async def chat(self, *args, **kwargs):
            return {
                "text": "bad metrics",
                "tool_calls": [],
                "input_tokens": -1,
                "output_tokens": 2,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "stop_reason": "end_turn",
                "model": self.model,
                "tool_call_dialect": "none",
                "reasoning_applied": False,
            }

    router = Router({"groq": _PoisonedProvider()}, ["groq"])
    app_client.app.state.router = router

    response = app_client.post(
        "/v1/chat",
        json={"prompt": "hello", "provider": "groq"},
        headers={"Authorization": f"Bearer {install_token}"},
    )

    assert response.status_code == 502
    assert router.state["groq"].tokens_today == 0
    rows = db.recent()
    assert len(rows) == 1
    assert rows[0]["status"] == "error"
    assert rows[0]["input_tokens"] == 0


def test_modal_cost_writer_owns_volume_and_verifies_gateway_signature(monkeypatch, tmp_path):
    import modal_app

    key = "k" * 32
    volume = _FakeVolume()
    monkeypatch.setenv(db.SIGNING_KEY_ENV, key)
    monkeypatch.setattr(modal_app, "cost_volume", volume)
    monkeypatch.setattr(modal_app, "_COST_DB_PATH", str(tmp_path / "cost.sqlite"))

    record = db.build_record(provider="test", model="test-model", input_tokens=7)
    signature = db.sign_record(record, key.encode())
    modal_app._run_cost_operation("append", {"record": record, "signature": signature})

    tampered = {**record, "output_tokens": 1}
    with pytest.raises(db.InvalidCostRecord, match="signature"):
        modal_app._run_cost_operation("append", {"record": tampered, "signature": signature})

    assert modal_app._run_cost_operation("aggregate", {"call_role": None})["test"]["in_tok"] == 7
    assert volume.reloads == 3
    assert volume.commits == 2


def test_modal_cost_boundary_excludes_adapter_and_gateway_volumes():
    import modal_app

    writer_secret_names = [secret.name for secret in modal_app.cost_ledger_writer.spec.secrets]
    gateway_secret_names = [secret.name for secret in modal_app.fastapi_app.spec.secrets]

    assert writer_secret_names == ["glc-cost-ledger-signing-key"]
    assert gateway_secret_names == [
        "glc-llm-keys",
        "glc-cost-ledger-signing-key",
        "glc-image-url-config",
    ]
    assert modal_app.cost_ledger_writer.spec.volumes["/cost"].name == "glc-cost"
    assert "/cost" not in modal_app.fastapi_app.spec.volumes
    assert "GLC_COST_LEDGER_SIGNING_KEY" not in modal_app._ADAPTER_IMAGE_ENV


def test_modal_proxy_signs_validated_record(monkeypatch):
    import modal_app

    key = b"p" * 32
    calls: list[tuple[str, dict[str, Any]]] = []

    def remote(operation: str, payload: dict[str, Any]) -> None:
        calls.append((operation, payload))

    monkeypatch.setattr(modal_app.cost_ledger_writer, "remote", remote)
    ledger = modal_app.ModalCostLedger(key)
    ledger.log_call(provider="test", model="test-model", input_tokens=4)

    operation, payload = calls[0]
    assert operation == "append"
    db.verify_record(payload["record"], payload["signature"], key)

    with pytest.raises(db.InvalidCostRecord, match="output_tokens"):
        ledger.log_call(provider="test", model="test-model", output_tokens=-1)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_modal_proxy_uses_async_remote_writer(monkeypatch):
    import modal_app

    key = b"p" * 32
    calls: list[tuple[str, dict[str, Any]]] = []

    async def remote(operation: str, payload: dict[str, Any]) -> None:
        calls.append((operation, payload))

    monkeypatch.setattr(modal_app.cost_ledger_writer, "remote", SimpleNamespace(aio=remote))
    db.configure_ledger(modal_app.ModalCostLedger(key))

    await db.alog_call(provider="test", model="test-model", input_tokens=4)

    operation, payload = calls[0]
    assert operation == "append"
    db.verify_record(payload["record"], payload["signature"], key)
