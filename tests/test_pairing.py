"""Pairing flow — code generation, expiry, validation."""

from __future__ import annotations

import time

import pytest

from glc.security.pairing import (
    CODE_TTL_SECONDS,
    PAIRING_ATTEMPT_LIMIT,
    PAIRING_LOCKOUT_SECONDS,
    PairingLockedOut,
    PairingStore,
)


def test_issue_code_is_six_digits():
    store = PairingStore()
    code, exp = store.issue_code("telegram", "42", "me")
    assert len(code) == 6 and code.isdigit()
    assert exp > time.time()


def test_confirm_creates_pairing():
    store = PairingStore()
    code, _ = store.issue_code("telegram", "42", "me", requested_trust_level="user_paired")
    rec = store.confirm_code(code)
    assert rec is not None
    assert rec.trust_level == "user_paired"
    assert store.lookup("telegram", "42") is not None


def test_expired_code_is_rejected(monkeypatch):
    store = PairingStore()
    code, _ = store.issue_code("telegram", "42", "me")
    # Move time forward past the TTL
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + CODE_TTL_SECONDS + 1)
    assert store.confirm_code(code) is None


def test_unknown_code_returns_none():
    store = PairingStore()
    assert store.confirm_code("000000") is None


def test_failed_attempts_lock_only_that_client():
    store = PairingStore()
    code, _ = store.issue_code("telegram", "42")

    for _ in range(PAIRING_ATTEMPT_LIMIT):
        assert store.confirm_code("000000", attempt_key="client-a") is None

    with pytest.raises(PairingLockedOut) as exc_info:
        store.confirm_code(code, attempt_key="client-a")
    assert exc_info.value.retry_after == PAIRING_LOCKOUT_SECONDS
    assert store.confirm_code(code, attempt_key="client-b") is not None


def test_pairing_attempts_persist_across_store_instances():
    for _ in range(PAIRING_ATTEMPT_LIMIT):
        assert PairingStore().confirm_code("000000", attempt_key="client-a") is None

    with pytest.raises(PairingLockedOut):
        PairingStore().confirm_code("000000", attempt_key="client-a")


def test_pairing_lockout_expires(monkeypatch):
    store = PairingStore()
    real_time = time.time
    for _ in range(PAIRING_ATTEMPT_LIMIT):
        assert store.confirm_code("000000", attempt_key="client-a") is None

    monkeypatch.setattr(time, "time", lambda: real_time() + PAIRING_LOCKOUT_SECONDS + 1)
    assert store.confirm_code("000000", attempt_key="client-a") is None


def test_owner_paired_classification():
    store = PairingStore()
    rec = store.force_pair_owner("webui", "owner-1")
    assert rec.trust_level == "owner_paired"
    found = store.lookup("webui", "owner-1")
    assert found is not None
    assert found.trust_level == "owner_paired"


def test_owners_only_returns_owner_paired():
    store = PairingStore()
    store.force_pair_owner("telegram", "owner-1")
    code, _ = store.issue_code("telegram", "user-1", requested_trust_level="user_paired")
    store.confirm_code(code)
    owners = store.owners(channel="telegram")
    assert len(owners) == 1
    assert owners[0].channel_user_id == "owner-1"


def test_revoke_removes_pairing():
    store = PairingStore()
    store.force_pair_owner("matrix", "owner-1")
    assert store.revoke("matrix", "owner-1") is True
    assert store.lookup("matrix", "owner-1") is None


def test_code_collision_replaces_pending():
    store = PairingStore()
    code1, _ = store.issue_code("slack", "U1")
    code2, _ = store.issue_code("slack", "U1")
    # Two requests for the same user: latest pending wins (sane UX —
    # the user shouldn't have to remember which old code is live).
    if code1 != code2:
        assert store.confirm_code(code2) is not None
