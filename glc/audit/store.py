"""Append-only SQLite audit log.

Every channel message, agent decision, policy verdict, and tool dispatch
lands here. SQLite triggers reject updates and deletes. Every row includes
the previous row hash and its own SHA-256 hash, making modification,
deletion, or reordering detectable.

Each append commits immediately so writes survive a hard kill.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))


def _resolve_path() -> str:
    """Resolve at call time, not import time, so tests that swap the env
    var see the change."""
    return os.getenv("GLC_AUDIT_DB", str(DEFAULT_DIR / "audit.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)  # autocommit; each insert flushes
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"
_GENESIS_HASH = "0" * 64
_HASH_FIELDS = (
    "ts",
    "session_id",
    "channel",
    "channel_user_id",
    "trust_level",
    "event_type",
    "tool",
    "policy_verdict",
    "params_json",
    "result_json",
)


def _entry_hash(previous_hash: str, values: dict[str, Any]) -> str:
    payload = {"prev_hash": previous_hash, **{field: values[field] for field in _HASH_FIELDS}}
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _install_immutable_triggers(c: sqlite3.Connection) -> None:
    c.execute(
        """
        CREATE TRIGGER IF NOT EXISTS audit_log_no_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit log is append-only');
        END
        """
    )
    c.execute(
        """
        CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
        BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit log is append-only');
        END
        """
    )


def _migrate_hash_chain(c: sqlite3.Connection) -> None:
    version_row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
    version = int(version_row["v"] or 0)
    columns = {row["name"] for row in c.execute("PRAGMA table_info(audit_log)")}
    if version >= 2 and {"prev_hash", "entry_hash"} <= columns:
        _install_immutable_triggers(c)
        return

    c.execute("BEGIN IMMEDIATE")
    try:
        c.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
        c.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
        if "prev_hash" not in columns:
            c.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
        if "entry_hash" not in columns:
            c.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")

        previous_hash = _GENESIS_HASH
        rows = c.execute(
            f"SELECT id, {', '.join(_HASH_FIELDS)} FROM audit_log ORDER BY id"  # noqa: S608
        ).fetchall()
        for row in rows:
            values = dict(row)
            current_hash = _entry_hash(previous_hash, values)
            c.execute(
                "UPDATE audit_log SET prev_hash=?, entry_hash=? WHERE id=?",
                (previous_hash, current_hash, row["id"]),
            )
            previous_hash = current_hash

        c.execute(
            "INSERT OR IGNORE INTO audit_schema(version, applied_at) VALUES (2, ?)",
            (time.time(),),
        )
        _install_immutable_triggers(c)
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise


def init_store() -> None:
    get_store().init()


async def ainit_store() -> None:
    await _async_store_call("init")


def _jsonify(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, default=str)
    except Exception:
        return json.dumps({"_repr": repr(v)})


class AuditStore:
    """Application-layer write-once store. The class deliberately exposes
    no update or delete methods. Reads (for the replay viewer) live in
    query() which is read-only."""

    def init(self) -> None:
        with _conn() as c:
            c.executescript(_SCHEMA_PATH.read_text())
            _migrate_hash_chain(c)

    def append(
        self,
        *,
        channel: str,
        channel_user_id: str,
        trust_level: str,
        event_type: str,
        session_id: str | None = None,
        tool: str | None = None,
        policy_verdict: str | None = None,
        params: Any = None,
        result: Any = None,
    ) -> int:
        values = {
            "ts": time.time(),
            "session_id": session_id,
            "channel": channel,
            "channel_user_id": channel_user_id,
            "trust_level": trust_level,
            "event_type": event_type,
            "tool": tool,
            "policy_verdict": policy_verdict,
            "params_json": _jsonify(params),
            "result_json": _jsonify(result),
        }
        with _conn() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                previous = c.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
                previous_hash = previous["entry_hash"] if previous is not None else _GENESIS_HASH
                if not isinstance(previous_hash, str) or len(previous_hash) != 64:
                    raise RuntimeError("audit hash chain is invalid")
                current_hash = _entry_hash(previous_hash, values)
                cur = c.execute(
                    """INSERT INTO audit_log
                       (ts, session_id, channel, channel_user_id, trust_level,
                        event_type, tool, policy_verdict, params_json, result_json,
                        prev_hash, entry_hash)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        *(values[field] for field in _HASH_FIELDS),
                        previous_hash,
                        current_hash,
                    ),
                )
                c.execute("COMMIT")
                return int(cur.lastrowid or 0)
            except Exception:
                c.execute("ROLLBACK")
                raise

    def verify_chain(self) -> bool:
        previous_hash = _GENESIS_HASH
        with _conn() as c:
            rows = c.execute(
                f"SELECT prev_hash, entry_hash, {', '.join(_HASH_FIELDS)} "  # noqa: S608
                "FROM audit_log ORDER BY id"
            ).fetchall()
        for row in rows:
            values = dict(row)
            if values.pop("prev_hash") != previous_hash:
                return False
            entry_hash = values.pop("entry_hash")
            if entry_hash != _entry_hash(previous_hash, values):
                return False
            previous_hash = entry_hash
        return True

    def query(
        self,
        limit: int = 100,
        session_id: str | None = None,
        channel: str | None = None,
    ) -> list[dict]:
        q = "SELECT * FROM audit_log"
        where: list[str] = []
        args: list[Any] = []
        if session_id:
            where.append("session_id=?")
            args.append(session_id)
        if channel:
            where.append("channel=?")
            args.append(channel)
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        with _conn() as c:
            return [dict(r) for r in c.execute(q, args).fetchall()]

    def schema_version(self) -> int:
        with _conn() as c:
            row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
            return int(row["v"] or 0)


_singleton: AuditStore | None = None


def get_store() -> AuditStore:
    global _singleton
    if _singleton is None:
        _singleton = AuditStore()
        _singleton.init()
    return _singleton


def configure_store(audit_store: AuditStore) -> None:
    """Replace the local store with a deployment-owned writer proxy."""

    global _singleton
    _singleton = audit_store


async def _async_store_call(method: str, *args: Any, **kwargs: Any) -> Any:
    store = get_store()
    async_method = getattr(store, f"a{method}", None)
    if async_method is not None:
        return await async_method(*args, **kwargs)
    return await asyncio.to_thread(getattr(store, method), *args, **kwargs)


def append(**kwargs: Any) -> int:
    return get_store().append(**kwargs)


async def aappend(**kwargs: Any) -> int:
    return await _async_store_call("append", **kwargs)


def query(limit: int = 100, session_id: str | None = None, channel: str | None = None) -> list[dict]:
    return get_store().query(limit=limit, session_id=session_id, channel=channel)


def schema_version() -> int:
    return get_store().schema_version()


def verify_chain() -> bool:
    return get_store().verify_chain()
