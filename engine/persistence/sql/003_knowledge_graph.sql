-- Migration 003: tablas para knowledge graph

CREATE TABLE IF NOT EXISTS ares_assets (
    id          BIGSERIAL PRIMARY KEY,
    asset_id    TEXT NOT NULL UNIQUE,
    asset_type  TEXT NOT NULL,  -- host/domain/url/service/technology/finding
    value       TEXT NOT NULL,
    metadata    JSONB DEFAULT '{}',
    first_seen  TIMESTAMPTZ DEFAULT NOW(),
    last_seen   TIMESTAMPTZ DEFAULT NOW(),
    scan_id     TEXT REFERENCES ares_scans(scan_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS ares_asset_relations (
    id          BIGSERIAL PRIMARY KEY,
    from_id     TEXT NOT NULL REFERENCES ares_assets(asset_id) ON DELETE CASCADE,
    to_id       TEXT NOT NULL REFERENCES ares_assets(asset_id) ON DELETE CASCADE,
    relation    TEXT NOT NULL,  -- resolves_to/exposes/hosted_on/uses_technology/etc
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (from_id, to_id, relation)
);

CREATE INDEX IF NOT EXISTS ares_assets_type ON ares_assets(asset_type);
CREATE INDEX IF NOT EXISTS ares_assets_scan ON ares_assets(scan_id);
CREATE INDEX IF NOT EXISTS ares_relations_from ON ares_asset_relations(from_id);
CREATE INDEX IF NOT EXISTS ares_relations_to ON ares_asset_relations(to_id);
