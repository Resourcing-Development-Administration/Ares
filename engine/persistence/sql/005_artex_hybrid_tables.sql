-- Migration 005: ARTEX hybrid tables
-- New subsystems: credentials, templates, archives, LLM usage,
-- intercept audit (persistent), company scope, skill gaps, cold graph digests.

-- Task credentials: per-task auth material (encrypted at rest via app layer)
CREATE TABLE IF NOT EXISTS task_credentials (
    id          BIGSERIAL PRIMARY KEY,
    task_id     TEXT        NOT NULL,
    label       TEXT        NOT NULL,          -- human name, e.g. "admin token"
    kind        TEXT        NOT NULL,          -- bearer|basic|cookie|apikey|custom
    ciphertext  BYTEA       NOT NULL,          -- AES-256-GCM encrypted value
    nonce       BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS task_credentials_task_id ON task_credentials(task_id);

-- Task templates: reusable scan configuration presets
CREATE TABLE IF NOT EXISTS task_templates (
    id          TEXT        PRIMARY KEY,       -- slugified name
    name        TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    config      JSONB       NOT NULL DEFAULT '{}',
    created_by  TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Task archives: compressed finished-task snapshots (ARTEX cold storage)
CREATE TABLE IF NOT EXISTS task_archives (
    id          BIGSERIAL PRIMARY KEY,
    task_id     TEXT        NOT NULL UNIQUE,
    scan_id     TEXT,
    target      TEXT        NOT NULL DEFAULT '',
    findings_count INT      NOT NULL DEFAULT 0,
    score_json  JSONB,
    archive_gz  BYTEA,                         -- gzipped ScanReport JSON; NULL = external path
    archive_path TEXT,                         -- S3 / local path if not stored inline
    archived_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS task_archives_task_id ON task_archives(task_id);
CREATE INDEX IF NOT EXISTS task_archives_archived_at ON task_archives(archived_at);

-- LLM usage log: persistent companion to llmrec JSONL
CREATE TABLE IF NOT EXISTS llm_usage (
    id              BIGSERIAL PRIMARY KEY,
    task_id         TEXT,
    provider        TEXT        NOT NULL,
    model           TEXT        NOT NULL,
    prompt_tokens   INT         NOT NULL DEFAULT 0,
    completion_tokens INT       NOT NULL DEFAULT 0,
    latency_ms      REAL,
    cache_hit       BOOLEAN     NOT NULL DEFAULT FALSE,
    error           TEXT,
    recorded_at     TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS llm_usage_task_id    ON llm_usage(task_id);
CREATE INDEX IF NOT EXISTS llm_usage_provider   ON llm_usage(provider, model);
CREATE INDEX IF NOT EXISTS llm_usage_recorded   ON llm_usage(recorded_at);

-- Intercept audit log: persistent version of the in-memory circular buffer in guard.py
CREATE TABLE IF NOT EXISTS intercept_audit (
    id          BIGSERIAL PRIMARY KEY,
    task_id     TEXT,
    tool_name   TEXT        NOT NULL,
    arguments   JSONB       NOT NULL DEFAULT '{}',
    decision    TEXT        NOT NULL,          -- APPROVED|DENIED|PENDING_HUMAN
    risk_score  INT,
    judge_used  BOOLEAN     NOT NULL DEFAULT FALSE,
    duration_ms REAL,
    operator    TEXT,                          -- who approved/denied (null = automatic)
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS intercept_audit_task_id  ON intercept_audit(task_id);
CREATE INDEX IF NOT EXISTS intercept_audit_decision ON intercept_audit(decision);
CREATE INDEX IF NOT EXISTS intercept_audit_tool     ON intercept_audit(tool_name);

-- Company scope: multi-tenant authorized target definitions
CREATE TABLE IF NOT EXISTS company_scope (
    id          BIGSERIAL PRIMARY KEY,
    org_id      TEXT        NOT NULL,          -- tenant identifier
    scope_type  TEXT        NOT NULL,          -- domain|ip_range|url_prefix|asn
    value       TEXT        NOT NULL,
    label       TEXT,
    environment TEXT        NOT NULL DEFAULT 'production',
    active      BOOLEAN     NOT NULL DEFAULT TRUE,
    added_by    TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (org_id, scope_type, value)
);
CREATE INDEX IF NOT EXISTS company_scope_org ON company_scope(org_id);

-- Skill gaps: tracks which skills were attempted but could not complete due to missing tools/auth
CREATE TABLE IF NOT EXISTS skill_gaps (
    id          BIGSERIAL PRIMARY KEY,
    task_id     TEXT,
    skill_name  TEXT        NOT NULL,
    gap_type    TEXT        NOT NULL,          -- missing_tool|no_auth|no_lab|scope_denied
    detail      TEXT        NOT NULL DEFAULT '',
    resolved    BOOLEAN     NOT NULL DEFAULT FALSE,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS skill_gaps_task_id    ON skill_gaps(task_id);
CREATE INDEX IF NOT EXISTS skill_gaps_skill_name ON skill_gaps(skill_name);

-- Cold graph digests: persists Compactor outputs so hot restarts can reload compacted context
CREATE TABLE IF NOT EXISTS digest (
    id          BIGSERIAL PRIMARY KEY,
    task_id     TEXT        NOT NULL,
    round       INT         NOT NULL DEFAULT 0,
    node_ids    JSONB       NOT NULL DEFAULT '[]', -- list of compacted GraphNode ids
    summary     TEXT        NOT NULL,
    tokens_saved INT        NOT NULL DEFAULT 0,
    model       TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (task_id, round)
);
CREATE INDEX IF NOT EXISTS digest_task_id ON digest(task_id);
