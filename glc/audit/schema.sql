-- glc_v1 audit log. AuditStore installs database triggers that reject
-- UPDATE and DELETE after schema migration/backfill completes.

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    session_id      TEXT,
    channel         TEXT    NOT NULL,
    channel_user_id TEXT    NOT NULL,
    trust_level     TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    tool            TEXT,
    policy_verdict  TEXT,
    params_json     TEXT,
    result_json     TEXT,
    prev_hash       TEXT,
    entry_hash      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_channel ON audit_log(channel, ts DESC);

-- Schema version 2 adds the hash-chain columns and immutable-row triggers.
-- AuditStore performs the migration so existing version-1 rows can be
-- backfilled before UPDATE is permanently denied.
CREATE TABLE IF NOT EXISTS audit_schema (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);
INSERT OR IGNORE INTO audit_schema (version, applied_at) VALUES (1, strftime('%s','now'));
