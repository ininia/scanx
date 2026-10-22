-- +goose Up
-- SBOM inventory (from full repository scans) and continuous vulnerability
-- monitoring against the OSV database.

CREATE TABLE sbom_components (
    id         uuid PRIMARY KEY,
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    project_id uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    scan_id    uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    ecosystem  text NOT NULL,
    name       text NOT NULL,
    version    text NOT NULL,
    purl       text NOT NULL,
    licenses   text[] NOT NULL DEFAULT '{}',
    UNIQUE (project_id, purl)
);
CREATE INDEX sbom_components_org_idx ON sbom_components (org_id, ecosystem, name);

CREATE TABLE vuln_matches (
    id            uuid PRIMARY KEY,
    org_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    project_id    uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    ecosystem     text NOT NULL,
    name          text NOT NULL,
    version       text NOT NULL,
    vuln_id       text NOT NULL,
    cve           text NOT NULL DEFAULT '',
    aliases       text[] NOT NULL DEFAULT '{}',
    severity      text NOT NULL,
    summary       text NOT NULL DEFAULT '',
    fixed_version text NOT NULL DEFAULT '',
    published     text NOT NULL DEFAULT '',
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at   timestamptz,
    notified      boolean NOT NULL DEFAULT false,
    UNIQUE (project_id, ecosystem, name, version, vuln_id)
);
CREATE INDEX vuln_matches_org_idx ON vuln_matches (org_id, resolved_at, severity);

-- Monitor runs (instance-wide; not tenant data).
CREATE TABLE vulnmon_runs (
    id           uuid PRIMARY KEY,
    requested_at timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz,
    status       text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    advisories   int NOT NULL DEFAULT 0,
    matches      int NOT NULL DEFAULT 0,
    new_matches  int NOT NULL DEFAULT 0,
    log          text NOT NULL DEFAULT ''
);
GRANT SELECT, INSERT, UPDATE, DELETE ON vulnmon_runs TO scanx_app;

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['sbom_components', 'vuln_matches'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON %I USING (org_id = scanx_current_org() OR scanx_is_superadmin())
                        WITH CHECK (org_id = scanx_current_org() OR scanx_is_superadmin())', t || '_tenant', t);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO scanx_app', t);
    END LOOP;
END $$;
-- +goose StatementEnd

UPDATE notification_channels SET events = events || ARRAY['sbom.vuln']
WHERE 'gate.failed' = ANY (events) OR 'scan.failed' = ANY (events);

-- +goose Down
UPDATE notification_channels SET events = array_remove(events, 'sbom.vuln');
DROP TABLE vulnmon_runs, vuln_matches, sbom_components;
