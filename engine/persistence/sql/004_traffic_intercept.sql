-- Migration 004: tabla para tráfico interceptado (proxy)

CREATE TABLE IF NOT EXISTS ares_traffic (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES ares_scans(scan_id) ON DELETE CASCADE,
    recorded_at TIMESTAMPTZ DEFAULT NOW(),
    method      TEXT,
    url         TEXT,
    request_headers  JSONB DEFAULT '{}',
    request_body     TEXT,
    response_status  SMALLINT,
    response_headers JSONB DEFAULT '{}',
    response_body    TEXT,
    duration_ms      INTEGER,
    flagged          BOOLEAN DEFAULT FALSE,
    flag_reason      TEXT
);

CREATE INDEX IF NOT EXISTS ares_traffic_scan ON ares_traffic(scan_id);
CREATE INDEX IF NOT EXISTS ares_traffic_flagged ON ares_traffic(scan_id, flagged) WHERE flagged = TRUE;
