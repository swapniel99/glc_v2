"""DM pairing flow.

A rotating six-digit code is issued per pairing request and expires after
five minutes. The owner enters the code through the WebUI to confirm.
Per-pairing trust levels live in ~/.glc/pairings.sqlite: owner_paired for
the installation owner, user_paired for explicitly-paired users.

The pairing store is sqlite-backed so it survives restarts.
"""

from __future__ import annotations

import math
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
CODE_TTL_SECONDS = 5 * 60
PAIRING_ATTEMPT_LIMIT = 5
PAIRING_ATTEMPT_WINDOW_SECONDS = 5 * 60
PAIRING_LOCKOUT_SECONDS = 15 * 60


class PairingLockedOut(Exception):
    """Pairing confirmations from one client are temporarily locked."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("pairing confirmation temporarily locked")
        self.retry_after = retry_after


def _resolve_path() -> str:
    return os.getenv("GLC_PAIRING_DB", str(DEFAULT_DIR / "pairings.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


@dataclass
class PairingRecord:
    channel: str
    channel_user_id: str
    user_handle: str
    trust_level: str
    paired_at: float


class PairingStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with _conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS pairings (
                    channel TEXT NOT NULL,
                    channel_user_id TEXT NOT NULL,
                    user_handle TEXT,
                    trust_level TEXT NOT NULL,
                    paired_at REAL NOT NULL,
                    PRIMARY KEY (channel, channel_user_id)
                )"""
            )
            c.execute(
                """CREATE TABLE IF NOT EXISTS pending_codes (
                    code TEXT PRIMARY KEY,
                    channel TEXT NOT NULL,
                    channel_user_id TEXT NOT NULL,
                    user_handle TEXT,
                    requested_trust_level TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )"""
            )
            c.execute(
                """CREATE TABLE IF NOT EXISTS pairing_attempts (
                    attempt_key TEXT PRIMARY KEY,
                    window_started_at REAL NOT NULL,
                    failed_attempts INTEGER NOT NULL,
                    locked_until REAL NOT NULL
                )"""
            )

    def issue_code(
        self,
        channel: str,
        channel_user_id: str,
        user_handle: str = "",
        *,
        requested_trust_level: str = "user_paired",
    ) -> tuple[str, float]:
        code = f"{secrets.randbelow(1_000_000):06d}"
        expires_at = time.time() + CODE_TTL_SECONDS
        with _conn() as c:
            c.execute(
                """INSERT OR REPLACE INTO pending_codes
                   (code, channel, channel_user_id, user_handle,
                    requested_trust_level, expires_at) VALUES (?,?,?,?,?,?)""",
                (code, channel, channel_user_id, user_handle, requested_trust_level, expires_at),
            )
        return code, expires_at

    def confirm_code(self, code: str, *, attempt_key: str = "local") -> PairingRecord | None:
        with self._lock, _conn() as c:
            c.execute("BEGIN IMMEDIATE")
            now = time.time()
            attempt = c.execute(
                "SELECT * FROM pairing_attempts WHERE attempt_key=?", (attempt_key,)
            ).fetchone()
            if attempt is not None and float(attempt["locked_until"]) > now:
                c.execute("ROLLBACK")
                raise PairingLockedOut(max(1, math.ceil(float(attempt["locked_until"]) - now)))
            if attempt is not None and (
                float(attempt["locked_until"]) > 0
                or float(attempt["window_started_at"]) + PAIRING_ATTEMPT_WINDOW_SECONDS <= now
            ):
                c.execute("DELETE FROM pairing_attempts WHERE attempt_key=?", (attempt_key,))
                attempt = None

            row = c.execute("SELECT * FROM pending_codes WHERE code=?", (code,)).fetchone()
            if row is not None and float(row["expires_at"]) <= now:
                c.execute("DELETE FROM pending_codes WHERE code=?", (code,))
                row = None
            if row is None:
                failed_attempts = int(attempt["failed_attempts"]) + 1 if attempt is not None else 1
                window_started_at = float(attempt["window_started_at"]) if attempt is not None else now
                locked_until = (
                    now + PAIRING_LOCKOUT_SECONDS if failed_attempts >= PAIRING_ATTEMPT_LIMIT else 0.0
                )
                c.execute(
                    """INSERT OR REPLACE INTO pairing_attempts
                       (attempt_key, window_started_at, failed_attempts, locked_until)
                       VALUES (?, ?, ?, ?)""",
                    (attempt_key, window_started_at, failed_attempts, locked_until),
                )
                c.execute("COMMIT")
                return None

            paired_at = now
            c.execute(
                """INSERT OR REPLACE INTO pairings
                   (channel, channel_user_id, user_handle, trust_level, paired_at)
                   VALUES (?,?,?,?,?)""",
                (
                    row["channel"],
                    row["channel_user_id"],
                    row["user_handle"],
                    row["requested_trust_level"],
                    paired_at,
                ),
            )
            c.execute("DELETE FROM pending_codes WHERE code=?", (code,))
            c.execute("DELETE FROM pairing_attempts WHERE attempt_key=?", (attempt_key,))
            c.execute("COMMIT")
            return PairingRecord(
                channel=row["channel"],
                channel_user_id=row["channel_user_id"],
                user_handle=row["user_handle"] or "",
                trust_level=row["requested_trust_level"],
                paired_at=paired_at,
            )

    def lookup(self, channel: str, channel_user_id: str) -> PairingRecord | None:
        with _conn() as c:
            row = c.execute(
                "SELECT * FROM pairings WHERE channel=? AND channel_user_id=?",
                (channel, channel_user_id),
            ).fetchone()
            if row is None:
                return None
            return PairingRecord(
                channel=row["channel"],
                channel_user_id=row["channel_user_id"],
                user_handle=row["user_handle"] or "",
                trust_level=row["trust_level"],
                paired_at=float(row["paired_at"]),
            )

    def owners(self, channel: str | None = None) -> list[PairingRecord]:
        q = "SELECT * FROM pairings WHERE trust_level='owner_paired'"
        args: list = []
        if channel:
            q += " AND channel=?"
            args.append(channel)
        with _conn() as c:
            return [
                PairingRecord(
                    channel=r["channel"],
                    channel_user_id=r["channel_user_id"],
                    user_handle=r["user_handle"] or "",
                    trust_level=r["trust_level"],
                    paired_at=float(r["paired_at"]),
                )
                for r in c.execute(q, args).fetchall()
            ]

    def all_pairings(self) -> list[PairingRecord]:
        with _conn() as c:
            rows = c.execute("SELECT * FROM pairings").fetchall()
            return [
                PairingRecord(
                    channel=r["channel"],
                    channel_user_id=r["channel_user_id"],
                    user_handle=r["user_handle"] or "",
                    trust_level=r["trust_level"],
                    paired_at=float(r["paired_at"]),
                )
                for r in rows
            ]

    def revoke(self, channel: str, channel_user_id: str) -> bool:
        with _conn() as c:
            cur = c.execute(
                "DELETE FROM pairings WHERE channel=? AND channel_user_id=?",
                (channel, channel_user_id),
            )
            return cur.rowcount > 0

    def force_pair_owner(
        self, channel: str, channel_user_id: str, user_handle: str = "owner"
    ) -> PairingRecord:
        """Out-of-band pairing for the installation owner. Used by the
        installer to bootstrap the first owner identity. Not exposed
        through HTTP."""
        paired_at = time.time()
        with _conn() as c:
            c.execute(
                """INSERT OR REPLACE INTO pairings
                   (channel, channel_user_id, user_handle, trust_level, paired_at)
                   VALUES (?,?,?,?,?)""",
                (channel, channel_user_id, user_handle, "owner_paired", paired_at),
            )
        return PairingRecord(
            channel=channel,
            channel_user_id=channel_user_id,
            user_handle=user_handle,
            trust_level="owner_paired",
            paired_at=paired_at,
        )


_singleton: PairingStore | None = None


def get_pairing_store() -> PairingStore:
    global _singleton
    if _singleton is None:
        _singleton = PairingStore()
    return _singleton
