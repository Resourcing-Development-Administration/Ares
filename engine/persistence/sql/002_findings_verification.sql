-- Migration 002: columnas de verificación POE en ares_findings

ALTER TABLE ares_findings
    ADD COLUMN IF NOT EXISTS poe_level          SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS verification_status TEXT    NOT NULL DEFAULT 'unverified',
    ADD COLUMN IF NOT EXISTS verification_note   TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS counterevidence     TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS confidence_rationale TEXT   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS triage_status       TEXT    NOT NULL DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS verified_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS verified_by         TEXT;

CREATE INDEX IF NOT EXISTS ares_findings_verification ON ares_findings(verification_status);
CREATE INDEX IF NOT EXISTS ares_findings_triage ON ares_findings(triage_status);
CREATE INDEX IF NOT EXISTS ares_findings_poe ON ares_findings(poe_level);
