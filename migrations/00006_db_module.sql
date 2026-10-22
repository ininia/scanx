-- +goose Up
-- Database module (structure scanning through read-only accounts) and
-- per-organization module entitlements managed by the instance admin.

-- Which modules an organization may use. A missing row means "enabled with
-- default settings", so existing organizations keep everything they had.
CREATE TABLE org_modules (
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    module     text NOT NULL CHECK (module IN ('repo', 'db')),
    enabled    boolean NOT NULL DEFAULT true,
    settings   jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, module)
);

CREATE TABLE db_connections (
    id                  uuid PRIMARY KEY,
    org_id              uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name                text NOT NULL,
    engine              text NOT NULL CHECK (engine IN ('postgres', 'mysql', 'mssql')),
    host                text NOT NULL,
    port                int NOT NULL CHECK (port BETWEEN 1 AND 65535),
    database_name       text NOT NULL DEFAULT '',
    username            text NOT NULL,
    -- NULL after a failed read-only check: only read-only credentials are kept.
    password_enc        bytea,
    password_nonce      bytea,
    tls_mode            text NOT NULL DEFAULT 'require' CHECK (tls_mode IN ('disable', 'require', 'verify')),
    -- pending: check queued · verifying: running · ready: read-only verified ·
    -- rejected: the account can write (password wiped) · error: could not connect.
    status              text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'verifying', 'ready', 'rejected', 'error')),
    verify_result       jsonb NOT NULL DEFAULT '{}'::jsonb,
    verified_at         timestamptz,
    verify_locked_by    text NOT NULL DEFAULT '',
    verify_locked_until timestamptz,
    schedule            text NOT NULL DEFAULT 'off' CHECK (schedule IN ('off', 'hourly', 'daily', 'weekly')),
    schedule_hour       int NOT NULL DEFAULT 3 CHECK (schedule_hour BETWEEN 0 AND 23),
    schedule_weekday    int NOT NULL DEFAULT 1 CHECK (schedule_weekday BETWEEN 0 AND 6),
    next_run_at         timestamptz,
    exclude             text[] NOT NULL DEFAULT '{}',
    created_by          uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
CREATE INDEX db_connections_queue_idx ON db_connections (updated_at) WHERE status IN ('pending', 'verifying');
CREATE INDEX db_connections_schedule_idx ON db_connections (next_run_at) WHERE schedule <> 'off';

CREATE TABLE db_scans (
    id             uuid PRIMARY KEY,
    org_id         uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    connection_id  uuid NOT NULL REFERENCES db_connections (id) ON DELETE CASCADE,
    trigger        text NOT NULL CHECK (trigger IN ('manual', 'schedule', 'api')),
    triggered_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    status         text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'completed', 'failed', 'canceled')),
    status_reason  text NOT NULL DEFAULT '',
    locked_by      text NOT NULL DEFAULT '',
    locked_until   timestamptz,
    score          int,
    grade          text NOT NULL DEFAULT '',
    gate_result    text CHECK (gate_result IN ('pass', 'fail')),
    counts         jsonb NOT NULL DEFAULT '{}'::jsonb,
    summary        jsonb NOT NULL DEFAULT '{}'::jsonb,
    read_only      jsonb NOT NULL DEFAULT '{}'::jsonb,
    snapshot_gz    bytea,
    new_findings   int NOT NULL DEFAULT 0,
    fixed_findings int NOT NULL DEFAULT 0,
    log            text NOT NULL DEFAULT '',
    queued_at      timestamptz NOT NULL DEFAULT now(),
    started_at     timestamptz,
    finished_at    timestamptz
);
CREATE INDEX db_scans_connection_idx ON db_scans (connection_id, queued_at DESC);
CREATE INDEX db_scans_org_idx ON db_scans (org_id, queued_at DESC);
CREATE INDEX db_scans_queue_idx ON db_scans (queued_at) WHERE status IN ('queued', 'running');
-- One active scan per connection.
CREATE UNIQUE INDEX db_scans_one_active ON db_scans (connection_id) WHERE status IN ('queued', 'running');

CREATE TABLE db_findings (
    id            uuid PRIMARY KEY,
    org_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    scan_id       uuid NOT NULL REFERENCES db_scans (id) ON DELETE CASCADE,
    connection_id uuid NOT NULL REFERENCES db_connections (id) ON DELETE CASCADE,
    rule_id       text NOT NULL,
    category      text NOT NULL,
    severity      text NOT NULL,
    object_type   text NOT NULL,
    object        text NOT NULL,
    params        text[] NOT NULL DEFAULT '{}',
    details       text[] NOT NULL DEFAULT '{}',
    fingerprint   text NOT NULL,
    is_new        boolean NOT NULL DEFAULT false
);
CREATE INDEX db_findings_scan_idx ON db_findings (scan_id);

-- One rule profile per organization (JSON, see dbscan.Profile).
CREATE TABLE db_profiles (
    org_id     uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    profile    jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_by uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['db_connections', 'db_scans', 'db_findings', 'db_profiles'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON %I USING (org_id = scanx_current_org() OR scanx_is_superadmin())
                        WITH CHECK (org_id = scanx_current_org() OR scanx_is_superadmin())', t || '_tenant', t);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO scanx_app', t);
    END LOOP;
END $$;
-- +goose StatementEnd

-- Organizations can read their entitlements; only the instance admin
-- (superadmin scope) can change them.
ALTER TABLE org_modules ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_modules FORCE ROW LEVEL SECURITY;
CREATE POLICY org_modules_read ON org_modules FOR SELECT
    USING (org_id = scanx_current_org() OR scanx_is_superadmin());
CREATE POLICY org_modules_write ON org_modules FOR ALL
    USING (scanx_is_superadmin()) WITH CHECK (scanx_is_superadmin());
GRANT SELECT, INSERT, UPDATE, DELETE ON org_modules TO scanx_app;

-- Existing notification channels also receive the matching database events.
UPDATE notification_channels SET events = events || ARRAY['db.scan.completed'] WHERE 'scan.completed' = ANY (events);
UPDATE notification_channels SET events = events || ARRAY['db.gate.failed'] WHERE 'gate.failed' = ANY (events);
UPDATE notification_channels SET events = events || ARRAY['db.scan.failed'] WHERE 'scan.failed' = ANY (events);

-- +goose Down
UPDATE notification_channels SET events = array_remove(array_remove(array_remove(events,
    'db.scan.completed'), 'db.gate.failed'), 'db.scan.failed');
DROP TABLE db_profiles, db_findings, db_scans, db_connections, org_modules;
