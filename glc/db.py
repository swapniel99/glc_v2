"""Signed, gateway-owned per-call cost ledger.

Gateway code signs validated call records.  The production Modal deployment
sends those records to a single writer Function that alone mounts the cost
database.  Local development uses the same signed append path in-process.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
DB_PATH = str(DEFAULT_DIR / "gateway.sqlite")
SIGNING_KEY_ENV = "GLC_COST_LEDGER_SIGNING_KEY"

_MAX_TOKENS_PER_CALL = 10_000_000
_MAX_COUNTER = 100_000_000
_MAX_LATENCY_MS = 86_400_000
_MAX_TEXT = 65_536
_STATUSES = {"ok", "error"}
_RECORD_FIELDS = {
    "ts",
    "nonce",
    "provider",
    "model",
    "input_tokens",
    "output_tokens",
    "cache_create_tokens",
    "cache_read_tokens",
    "latency_ms",
    "status",
    "error",
    "prompt_chars",
    "response_chars",
    "override",
    "attempted",
    "tool_calls",
    "reasoning_applied",
    "tool_dialect",
    "call_role",
    "router_decision",
    "embed_dim",
    "agent",
    "session",
    "retries",
}
_INTEGER_LIMITS = {
    "input_tokens": _MAX_TOKENS_PER_CALL,
    "output_tokens": _MAX_TOKENS_PER_CALL,
    "cache_create_tokens": _MAX_TOKENS_PER_CALL,
    "cache_read_tokens": _MAX_TOKENS_PER_CALL,
    "latency_ms": _MAX_LATENCY_MS,
    "prompt_chars": _MAX_COUNTER,
    "response_chars": _MAX_COUNTER,
    "tool_calls": _MAX_COUNTER,
    "embed_dim": _MAX_COUNTER,
    "retries": _MAX_COUNTER,
}
_OPTIONAL_TEXT_FIELDS = {
    "error",
    "override",
    "attempted",
    "tool_dialect",
    "router_decision",
    "agent",
    "session",
}


class InvalidCostRecord(ValueError):
    """Cost record failed source authentication or metric validation."""


def signing_key_from_environment() -> bytes:
    value = os.getenv(SIGNING_KEY_ENV, "")
    if len(value.encode()) < 32:
        raise RuntimeError(f"{SIGNING_KEY_ENV} must contain at least 32 bytes")
    return value.encode()


def validate_usage_metrics(
    *,
    input_tokens: Any,
    output_tokens: Any,
    cache_create_tokens: Any = 0,
    cache_read_tokens: Any = 0,
) -> None:
    """Reject provider-supplied usage that could poison budgets or rollups."""

    values = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_create_tokens": cache_create_tokens,
        "cache_read_tokens": cache_read_tokens,
    }
    for field, value in values.items():
        if type(value) is not int or not 0 <= value <= _MAX_TOKENS_PER_CALL:
            raise InvalidCostRecord(f"invalid {field}")


def _validate_record(record: dict[str, Any]) -> None:
    if not isinstance(record, dict) or set(record) != _RECORD_FIELDS:
        raise InvalidCostRecord("invalid cost record fields")
    if type(record["ts"]) not in {int, float} or not 0 < record["ts"] < 10_000_000_000:
        raise InvalidCostRecord("invalid timestamp")
    if not isinstance(record["nonce"], str) or len(record["nonce"]) != 32:
        raise InvalidCostRecord("invalid nonce")
    try:
        bytes.fromhex(record["nonce"])
    except ValueError as exc:
        raise InvalidCostRecord("invalid nonce") from exc

    for field in ("provider", "model"):
        value = record[field]
        if not isinstance(value, str) or not value or len(value) > 256:
            raise InvalidCostRecord(f"invalid {field}")
    if record["status"] not in _STATUSES:
        raise InvalidCostRecord("invalid status")
    if type(record["reasoning_applied"]) is not bool:
        raise InvalidCostRecord("invalid reasoning_applied")

    for field, limit in _INTEGER_LIMITS.items():
        value = record[field]
        if field == "embed_dim" and value is None:
            continue
        if type(value) is not int or not 0 <= value <= limit:
            raise InvalidCostRecord(f"invalid {field}")
    for field in _OPTIONAL_TEXT_FIELDS:
        value = record[field]
        if value is not None and (not isinstance(value, str) or len(value) > _MAX_TEXT):
            raise InvalidCostRecord(f"invalid {field}")

    call_role = record["call_role"]
    if not isinstance(call_role, str) or not call_role or len(call_role) > 64:
        raise InvalidCostRecord("invalid call_role")

    validate_usage_metrics(
        input_tokens=record["input_tokens"],
        output_tokens=record["output_tokens"],
        cache_create_tokens=record["cache_create_tokens"],
        cache_read_tokens=record["cache_read_tokens"],
    )


def _canonical_record(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _validate_signing_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) < 32:
        raise RuntimeError("cost ledger signing key must contain at least 32 bytes")


def sign_record(record: dict[str, Any], key: bytes) -> str:
    _validate_record(record)
    _validate_signing_key(key)
    return hmac.new(key, _canonical_record(record), hashlib.sha256).hexdigest()


def verify_record(record: dict[str, Any], signature: str, key: bytes) -> None:
    _validate_record(record)
    _validate_signing_key(key)
    if not isinstance(signature, str) or len(signature) != 64:
        raise InvalidCostRecord("invalid cost record signature")
    expected = hmac.new(key, _canonical_record(record), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise InvalidCostRecord("invalid cost record signature")


def build_record(**values: Any) -> dict[str, Any]:
    record = {
        "ts": time.time(),
        "nonce": secrets.token_hex(16),
        "provider": values.get("provider"),
        "model": values.get("model"),
        "input_tokens": values.get("input_tokens", 0),
        "output_tokens": values.get("output_tokens", 0),
        "cache_create_tokens": values.get("cache_create_tokens", 0),
        "cache_read_tokens": values.get("cache_read_tokens", 0),
        "latency_ms": values.get("latency_ms", 0),
        "status": values.get("status", "ok"),
        "error": values.get("error"),
        "prompt_chars": values.get("prompt_chars", 0),
        "response_chars": values.get("response_chars", 0),
        "override": values.get("override"),
        "attempted": values.get("attempted"),
        "tool_calls": values.get("tool_calls", 0),
        "reasoning_applied": values.get("reasoning_applied", False),
        "tool_dialect": values.get("tool_dialect"),
        "call_role": values.get("call_role", "worker"),
        "router_decision": values.get("router_decision"),
        "embed_dim": values.get("embed_dim"),
        "agent": values.get("agent"),
        "session": values.get("session"),
        "retries": values.get("retries", 0),
    }
    _validate_record(record)
    return record


def _db_path() -> str:
    return os.getenv("GLC_GATEWAY_DB", DB_PATH)


def _ensure_parent() -> None:
    Path(_db_path()).parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def conn():
    _ensure_parent()
    connection = sqlite3.connect(_db_path())
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def _sqlite_init() -> None:
    with conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                input_tokens INTEGER DEFAULT 0 CHECK(input_tokens >= 0),
                output_tokens INTEGER DEFAULT 0 CHECK(output_tokens >= 0),
                cache_create_tokens INTEGER DEFAULT 0 CHECK(cache_create_tokens >= 0),
                cache_read_tokens INTEGER DEFAULT 0 CHECK(cache_read_tokens >= 0),
                latency_ms INTEGER DEFAULT 0 CHECK(latency_ms >= 0),
                status TEXT CHECK(status IN ('ok', 'error')),
                error TEXT,
                prompt_chars INTEGER DEFAULT 0 CHECK(prompt_chars >= 0),
                response_chars INTEGER DEFAULT 0 CHECK(response_chars >= 0),
                override TEXT,
                attempted TEXT,
                tool_calls INTEGER DEFAULT 0 CHECK(tool_calls >= 0),
                reasoning_applied INTEGER DEFAULT 0,
                tool_dialect TEXT,
                call_role TEXT DEFAULT 'worker',
                router_decision TEXT,
                embed_dim INTEGER,
                agent TEXT,
                session TEXT,
                retries INTEGER DEFAULT 0 CHECK(retries >= 0),
                writer_nonce TEXT,
                writer_signature TEXT
            )"""
        )
        columns = {row["name"] for row in c.execute("PRAGMA table_info(calls)")}
        if "writer_nonce" not in columns:
            c.execute("ALTER TABLE calls ADD COLUMN writer_nonce TEXT")
        if "writer_signature" not in columns:
            c.execute("ALTER TABLE calls ADD COLUMN writer_signature TEXT")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ts ON calls(ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_prov_ts ON calls(provider, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_role_ts ON calls(call_role, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_ts ON calls(agent, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_session_ts ON calls(session, ts DESC)")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_writer_nonce ON calls(writer_nonce)")


def append_signed(record: dict[str, Any], signature: str, key: bytes) -> None:
    """Verify one gateway signature, then append exactly once."""

    verify_record(record, signature, key)
    with conn() as c:
        try:
            c.execute(
                """INSERT INTO calls (
                    ts, provider, model, input_tokens, output_tokens,
                    cache_create_tokens, cache_read_tokens, latency_ms, status,
                    error, prompt_chars, response_chars, override, attempted,
                    tool_calls, reasoning_applied, tool_dialect, call_role,
                    router_decision, embed_dim, agent, session, retries,
                    writer_nonce, writer_signature
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    record["ts"],
                    record["provider"],
                    record["model"],
                    record["input_tokens"],
                    record["output_tokens"],
                    record["cache_create_tokens"],
                    record["cache_read_tokens"],
                    record["latency_ms"],
                    record["status"],
                    record["error"],
                    record["prompt_chars"],
                    record["response_chars"],
                    record["override"],
                    record["attempted"],
                    record["tool_calls"],
                    1 if record["reasoning_applied"] else 0,
                    record["tool_dialect"],
                    record["call_role"],
                    record["router_decision"],
                    record["embed_dim"],
                    record["agent"],
                    record["session"],
                    record["retries"],
                    record["nonce"],
                    signature,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise InvalidCostRecord("replayed cost record") from exc


def _sqlite_by_agent(session: str | None = None, since: float | None = None):
    where = ["ts >= ?"]
    args = [since if since is not None else (time.time() - (time.time() % 86400))]
    if session:
        where.append("session=?")
        args.append(session)
    query = (
        "SELECT agent, provider, COUNT(*) AS calls, "
        "SUM(input_tokens) AS in_tok, SUM(output_tokens) AS out_tok, "
        "SUM(latency_ms) AS total_latency_ms, "
        "SUM(retries) AS total_retries, "
        "SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) AS ok, "
        "SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors "
        "FROM calls WHERE " + " AND ".join(where) + " AND agent IS NOT NULL "
        "GROUP BY agent, provider"
    )
    with conn() as c:
        rows = c.execute(query, args).fetchall()
        out: dict[str, list[dict]] = {}
        for row in rows:
            out.setdefault(row["agent"], []).append(dict(row))
        return out


def _sqlite_recent(limit: int = 100, provider: str | None = None, status: str | None = None):
    query = "SELECT * FROM calls"
    where: list[str] = []
    args: list[Any] = []
    if provider:
        where.append("provider=?")
        args.append(provider)
    if status:
        where.append("status=?")
        args.append(status)
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with conn() as c:
        records = [dict(row) for row in c.execute(query, args).fetchall()]
    for record in records:
        record.pop("writer_nonce", None)
        record.pop("writer_signature", None)
    return records


def _sqlite_aggregate(call_role: str | None = None):
    now = time.time()
    day_start = now - (now % 86400)
    query = """SELECT provider,
                  COUNT(*) AS calls,
                  SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) AS ok_calls,
                  SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors,
                  SUM(input_tokens) AS in_tok,
                  SUM(output_tokens) AS out_tok,
                  SUM(cache_read_tokens) AS cache_reads,
                  SUM(cache_create_tokens) AS cache_creates,
                  SUM(tool_calls) AS tool_calls,
                  AVG(latency_ms) AS avg_latency,
                  MAX(ts) AS last_ts
             FROM calls WHERE ts >= ?"""
    args: list[Any] = [day_start]
    if call_role == "worker":
        query += " AND (call_role='worker' OR call_role IS NULL)"
    elif call_role == "router":
        query += " AND call_role LIKE 'router%'"
    elif call_role:
        query += " AND call_role=?"
        args.append(call_role)
    query += " GROUP BY provider"
    with conn() as c:
        rows = c.execute(query, args).fetchall()
        return {row["provider"]: dict(row) for row in rows}


class LocalSignedCostLedger:
    """In-process development backend; still validates and signs every write."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or secrets.token_bytes(32)

    def init(self) -> None:
        _sqlite_init()

    def log_call(self, **values: Any) -> None:
        record = build_record(**values)
        append_signed(record, sign_record(record, self._key), self._key)

    def by_agent(self, session: str | None = None, since: float | None = None):
        return _sqlite_by_agent(session=session, since=since)

    def recent(self, limit: int = 100, provider: str | None = None, status: str | None = None):
        return _sqlite_recent(limit=limit, provider=provider, status=status)

    def aggregate(self, call_role: str | None = None):
        return _sqlite_aggregate(call_role=call_role)


_ledger: Any = None


def configure_ledger(ledger: Any) -> None:
    global _ledger
    _ledger = ledger


def get_ledger() -> Any:
    global _ledger
    if _ledger is None:
        _ledger = LocalSignedCostLedger()
    return _ledger


def init() -> None:
    get_ledger().init()


async def _async_ledger_call(method: str, *args: Any, **kwargs: Any) -> Any:
    ledger = get_ledger()
    async_method = getattr(ledger, f"a{method}", None)
    if async_method is not None:
        return await async_method(*args, **kwargs)
    return await asyncio.to_thread(getattr(ledger, method), *args, **kwargs)


async def ainit() -> None:
    await _async_ledger_call("init")


def log_call(
    provider,
    model,
    input_tokens=0,
    output_tokens=0,
    latency_ms=0,
    status="ok",
    error=None,
    prompt_chars=0,
    response_chars=0,
    override=None,
    attempted=None,
    cache_create_tokens=0,
    cache_read_tokens=0,
    tool_calls=0,
    reasoning_applied=False,
    tool_dialect=None,
    call_role="worker",
    router_decision=None,
    embed_dim=None,
    agent=None,
    session=None,
    retries=0,
) -> None:
    get_ledger().log_call(
        provider=provider,
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        latency_ms=latency_ms,
        status=status,
        error=error,
        prompt_chars=prompt_chars,
        response_chars=response_chars,
        override=override,
        attempted=attempted,
        cache_create_tokens=cache_create_tokens,
        cache_read_tokens=cache_read_tokens,
        tool_calls=tool_calls,
        reasoning_applied=reasoning_applied,
        tool_dialect=tool_dialect,
        call_role=call_role,
        router_decision=router_decision,
        embed_dim=embed_dim,
        agent=agent,
        session=session,
        retries=retries,
    )


async def alog_call(**values: Any) -> None:
    await _async_ledger_call("log_call", **values)


def by_agent(session=None, since=None):
    return get_ledger().by_agent(session=session, since=since)


async def aby_agent(session=None, since=None):
    return await _async_ledger_call("by_agent", session=session, since=since)


def recent(limit=100, provider=None, status=None):
    return get_ledger().recent(limit=limit, provider=provider, status=status)


async def arecent(limit=100, provider=None, status=None):
    return await _async_ledger_call("recent", limit=limit, provider=provider, status=status)


def aggregate(call_role=None):
    return get_ledger().aggregate(call_role=call_role)


async def aaggregate(call_role=None):
    return await _async_ledger_call("aggregate", call_role=call_role)
