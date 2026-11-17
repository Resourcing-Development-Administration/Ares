-- Migration 001: schema inicial
-- Tablas base creadas originalmente en store.py::_CREATE_TABLES_SQL

CREATE TABLE IF NOT EXISTS ares_scans (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     TEXT NOT NULL UNIQUE,
    target_name TEXT NOT NULL,
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    score       JSONB,
    policy_verdict JSONB,
    mode        TEXT DEFAULT 'scan',
    findings_json JSONB DEFAULT '[]',
    report_json JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ares_findings (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES ares_scans(scan_id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    test_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    category    TEXT NOT NULL,
    target      TEXT,
    passed      BOOLEAN NOT NULL DEFAULT FALSE,
    confidence  TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ares_findings_scan_id ON ares_findings(scan_id);
CREATE INDEX IF NOT EXISTS ares_findings_fingerprint ON ares_findings(fingerprint);

CREATE TABLE IF NOT EXISTS ares_schedules (
    id          BIGSERIAL PRIMARY KEY,
    entry_id    TEXT NOT NULL UNIQUE,
    config_json JSONB NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
