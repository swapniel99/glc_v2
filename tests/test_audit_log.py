"""Append-only audit log — write correctness, restart survival,
no-update/no-delete surface."""

from __future__ import annotations

import sqlite3

import pytest

from glc.audit import store
from glc.audit.store import AuditStore, append, init_store, query, schema_version, verify_chain


def test_init_then_append():
    init_store()
    rid = append(
        channel="telegram",
        channel_user_id="42",
        trust_level="owner_paired",
        event_type="inbound_message",
        session_id="s1",
        params={"text": "hi"},
    )
    assert rid > 0
    rows = query(limit=5)
    assert len(rows) == 1
    assert rows[0]["channel"] == "telegram"
    assert rows[0]["event_type"] == "inbound_message"


def test_write_survives_restart(monkeypatch, tmp_path):
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="boot")
    store._singleton = None  # simulate process restart
    rows = query(limit=10)
    assert len(rows) == 1


def test_store_exposes_no_update_or_delete():
    s = AuditStore()
    assert not hasattr(s, "update")
    assert not hasattr(s, "delete")
    public = [n for n in dir(s) if not n.startswith("_")]
    assert "append" in public
    assert len([n for n in public if n in ("update", "delete", "modify")]) == 0


def test_schema_version_is_two():
    init_store()
    assert schema_version() == 2


def test_query_filters_by_session_and_channel():
    init_store()
    append(
        channel="discord", channel_user_id="1", trust_level="owner_paired", event_type="x", session_id="s-A"
    )
    append(
        channel="telegram", channel_user_id="1", trust_level="owner_paired", event_type="x", session_id="s-B"
    )
    rows = query(session_id="s-A")
    assert len(rows) == 1
    assert rows[0]["channel"] == "discord"
    rows = query(channel="telegram")
    assert len(rows) == 1


def test_jsonifies_complex_params():
    init_store()
    append(
        channel="x",
        channel_user_id="1",
        trust_level="owner_paired",
        event_type="x",
        params={"nested": {"k": [1, 2, 3]}},
    )
    rows = query(limit=1)
    assert "nested" in rows[0]["params_json"]


def test_rows_form_verifiable_hash_chain():
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="first")
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="second")

    rows = list(reversed(query(limit=10)))
    assert rows[0]["prev_hash"] == "0" * 64
    assert rows[1]["prev_hash"] == rows[0]["entry_hash"]
    assert verify_chain()


def test_database_rejects_update_and_delete():
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="immutable")

    with sqlite3.connect(store._resolve_path()) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE audit_log SET event_type='changed'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM audit_log")


def test_chain_verification_detects_offline_tampering():
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="original")

    with sqlite3.connect(store._resolve_path()) as connection:
        connection.execute("DROP TRIGGER audit_log_no_update")
        connection.execute("UPDATE audit_log SET event_type='changed'")

    assert not verify_chain()


def test_version_one_rows_are_hash_backfilled():
    path = store._resolve_path()
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                session_id TEXT,
                channel TEXT NOT NULL,
                channel_user_id TEXT NOT NULL,
                trust_level TEXT NOT NULL,
                event_type TEXT NOT NULL,
                tool TEXT,
                policy_verdict TEXT,
                params_json TEXT,
                result_json TEXT
            );
            CREATE TABLE audit_schema (version INTEGER PRIMARY KEY, applied_at REAL NOT NULL);
            INSERT INTO audit_schema VALUES (1, 1);
            INSERT INTO audit_log
                (ts, channel, channel_user_id, trust_level, event_type)
                VALUES (1, 'x', '1', 'owner_paired', 'legacy');
            """
        )

    audit_store = AuditStore()
    audit_store.init()
    assert audit_store.schema_version() == 2
    assert audit_store.verify_chain()
    assert audit_store.query(limit=1)[0]["entry_hash"]
