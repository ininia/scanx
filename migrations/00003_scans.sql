-- +goose Up
-- Faz 3–4: deploy keys, job queue, scans, findings, issues, webhooks, notifications.

ALTER TABLE projects ADD COLUMN webhook_secret_enc bytea;
ALTER TABLE projects ADD COLUMN webhook_secret_nonce bytea;
ALTER TABLE projects ADD COLUMN fail_on text NOT NULL DEFAULT 'high'
    CHECK (fail_on IN ('critical', 'high', 'medium', 'low', 'info', 'none'));
ALTER TABLE projects ADD COLUMN scan_history boolean NOT NULL DEFAULT true;

CREATE TABLE ssh_keys (
    id              uuid PRIMARY KEY,
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    project_id      uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    public_key      text NOT NULL,
    fingerprint     text NOT NULL,
    private_key_enc bytea NOT NULL,
    nonce           bytea NOT NULL,
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retiring', 'revoked')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    retired_at      timestamptz
);
CREATE UNIQUE INDEX ssh_keys_one_active ON ssh_keys (project_id) WHERE status = 'active';

-- Simple Postgres job queue (ADR-008): claimed with FOR UPDATE SKIP LOCKED.
CREATE TABLE jobs (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('scan', 'test_connection')),
    project_id   uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    scan_id      uuid,
    status       text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    result       jsonb NOT NULL DEFAULT '{}'::jsonb,
    error        text NOT NULL DEFAULT '',
    attempts     int NOT NULL DEFAULT 0,
    locked_by    text NOT NULL DEFAULT '',
    locked_until timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz
);
CREATE INDEX jobs_queue_idx ON jobs (created_at) WHERE status IN ('queued', 'running');

CREATE TABLE scans (
    id             uuid PRIMARY KEY,
    org_id         uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    project_id     uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    trigger        text NOT NULL CHECK (trigger IN ('webhook', 'schedule', 'manual', 'api', 'ci_upload')),
    triggered_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    branch         text NOT NULL,
    commit_sha     text NOT NULL DEFAULT '',
    commit_message text NOT NULL DEFAULT '',
    commit_author  text NOT NULL DEFAULT '',
    status         text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'cloning', 'scanning', 'reporting', 'completed', 'failed', 'canceled')),
    status_reason  text NOT NULL DEFAULT '',
    partial        boolean NOT NULL DEFAULT false,
    summary        jsonb NOT NULL DEFAULT '{}'::jsonb,
    gate_result    text CHECK (gate_result IN ('pass', 'fail', 'warn')),
    score          int,
    new_issues     int NOT NULL DEFAULT 0,
    fixed_issues   int NOT NULL DEFAULT 0,
    queued_at      timestamptz NOT NULL DEFAULT now(),
    started_at     timestamptz,
    finished_at    timestamptz,
    cleaned_at     timestamptz
);
CREATE INDEX scans_project_idx ON scans (project_id, queued_at DESC);
CREATE INDEX scans_org_idx ON scans (org_id, queued_at DESC);
-- At most one active scan per project and commit (idempotent triggers, spec §4.2).
CREATE UNIQUE INDEX scans_active_commit ON scans (project_id, branch, commit_sha)
    WHERE status IN ('queued', 'cloning', 'scanning', 'reporting') AND commit_sha <> '';

CREATE TABLE scan_tools (
    id             uuid PRIMARY KEY,
    org_id         uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    scan_id        uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    tool_id        text NOT NULL,
    name           text NOT NULL,
    tool_version   text NOT NULL DEFAULT '',
    status         text NOT NULL,
    duration_ms    bigint NOT NULL DEFAULT 0,
    findings_count int NOT NULL DEFAULT 0,
    error          text NOT NULL DEFAULT ''
);
CREATE INDEX scan_tools_scan_idx ON scan_tools (scan_id);

CREATE TABLE issues (
    id                 uuid PRIMARY KEY,
    org_id             uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    project_id         uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    fingerprint        text NOT NULL,
    category           text NOT NULL,
    severity           text NOT NULL,
    title              text NOT NULL,
    rule_id            text NOT NULL DEFAULT '',
    file               text NOT NULL DEFAULT '',
    start_line         int NOT NULL DEFAULT 0,
    cwe                text[] NOT NULL DEFAULT '{}',
    cve                text[] NOT NULL DEFAULT '{}',
    sources            text[] NOT NULL DEFAULT '{}',
    status             text NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'fixed', 'false_positive', 'accepted_risk', 'wont_fix')),
    status_reason      text NOT NULL DEFAULT '',
    detail             jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_seen_scan_id uuid,
    last_seen_scan_id  uuid,
    fixed_in_scan_id   uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, fingerprint)
);
CREATE INDEX issues_project_status_idx ON issues (project_id, status, severity);

CREATE TABLE scan_issues (
    scan_id  uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    issue_id uuid NOT NULL REFERENCES issues (id) ON DELETE CASCADE,
    org_id   uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    is_new   boolean NOT NULL DEFAULT false,
    PRIMARY KEY (scan_id, issue_id)
);

CREATE TABLE issue_events (
    id         uuid PRIMARY KEY,
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    issue_id   uuid NOT NULL REFERENCES issues (id) ON DELETE CASCADE,
    user_id    uuid REFERENCES users (id) ON DELETE SET NULL,
    kind       text NOT NULL,
    from_value text NOT NULL DEFAULT '',
    to_value   text NOT NULL DEFAULT '',
    comment    text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX issue_events_issue_idx ON issue_events (issue_id, created_at);

CREATE TABLE reports (
    id         uuid PRIMARY KEY,
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    scan_id    uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    format     text NOT NULL CHECK (format IN ('html', 'json', 'sarif', 'sbom')),
    content_gz bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scan_id, format)
);

CREATE TABLE webhook_deliveries (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    project_id  uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    provider    text NOT NULL,
    delivery_id text NOT NULL,
    event       text NOT NULL,
    result      text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, delivery_id)
);

CREATE TABLE notification_channels (
    id         uuid PRIMARY KEY,
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    kind       text NOT NULL CHECK (kind IN ('email', 'slack', 'teams', 'webhook')),
    name       text NOT NULL,
    target_enc bytea NOT NULL,
    nonce      bytea NOT NULL,
    events     text[] NOT NULL DEFAULT '{scan.completed,gate.failed}',
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Row-level security on every new org-scoped table.
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['ssh_keys','jobs','scans','scan_tools','issues','scan_issues','issue_events',
                             'reports','webhook_deliveries','notification_channels'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON %I USING (org_id = scanx_current_org() OR scanx_is_superadmin())
                        WITH CHECK (org_id = scanx_current_org() OR scanx_is_superadmin())', t || '_tenant', t);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO scanx_app', t);
    END LOOP;
END $$;
-- +goose StatementEnd

-- Webhooks arrive without a tenant context: this returns only the routing
-- data of one project, by id.
-- +goose StatementBegin
CREATE FUNCTION scanx_lookup_webhook_project(p_id uuid)
    RETURNS TABLE (id uuid, org_id uuid, provider text, branches text[],
                   webhook_secret_enc bytea, webhook_secret_nonce bytea, archived boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
$$ SELECT p.id, p.org_id, p.provider, p.branches, p.webhook_secret_enc, p.webhook_secret_nonce,
          p.archived_at IS NOT NULL
   FROM projects p WHERE p.id = p_id $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION scanx_lookup_webhook_project(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION scanx_lookup_webhook_project(uuid) TO scanx_app;

-- +goose Down
DROP FUNCTION scanx_lookup_webhook_project(uuid);
DROP TABLE notification_channels, webhook_deliveries, reports, issue_events, scan_issues, issues,
    scan_tools, scans, jobs, ssh_keys;
ALTER TABLE projects DROP COLUMN scan_history, DROP COLUMN fail_on,
    DROP COLUMN webhook_secret_nonce, DROP COLUMN webhook_secret_enc;
