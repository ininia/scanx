-- +goose Up
-- Certificate, domain and TLS monitoring. Also opens org_modules to the
-- modules that follow (sbom, dast).

ALTER TABLE org_modules DROP CONSTRAINT org_modules_module_check;
ALTER TABLE org_modules ADD CONSTRAINT org_modules_module_check
    CHECK (module IN ('repo', 'db', 'tls', 'sbom', 'dast'));

CREATE TABLE monitored_domains (
    id              uuid PRIMARY KEY,
    org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    host            text NOT NULL,
    port            int NOT NULL DEFAULT 443 CHECK (port BETWEEN 1 AND 65535),
    label           text NOT NULL DEFAULT '',
    enabled         boolean NOT NULL DEFAULT true,
    schedule        text NOT NULL DEFAULT 'daily' CHECK (schedule IN ('hourly', 'daily')),
    next_check_at   timestamptz NOT NULL DEFAULT now(),
    locked_until    timestamptz,
    last_check_id   uuid,
    last_checked_at timestamptz,
    last_score      int,
    last_grade      text NOT NULL DEFAULT '',
    last_error      text NOT NULL DEFAULT '',
    cert_not_after  timestamptz,
    cert_issuer     text NOT NULL DEFAULT '',
    -- Smallest expiry threshold (30/14/7/1/0 days) already notified, so
    -- every threshold alerts once per certificate.
    alerted_days    int,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, host, port)
);
CREATE INDEX monitored_domains_due_idx ON monitored_domains (next_check_at) WHERE enabled;

CREATE TABLE domain_checks (
    id         uuid PRIMARY KEY,
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id  uuid NOT NULL REFERENCES monitored_domains (id) ON DELETE CASCADE,
    checked_at timestamptz NOT NULL DEFAULT now(),
    score      int NOT NULL DEFAULT 0,
    grade      text NOT NULL DEFAULT '',
    counts     jsonb NOT NULL DEFAULT '{}'::jsonb,
    result     jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX domain_checks_domain_idx ON domain_checks (domain_id, checked_at DESC);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['monitored_domains', 'domain_checks'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON %I USING (org_id = scanx_current_org() OR scanx_is_superadmin())
                        WITH CHECK (org_id = scanx_current_org() OR scanx_is_superadmin())', t || '_tenant', t);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO scanx_app', t);
    END LOOP;
END $$;
-- +goose StatementEnd

UPDATE notification_channels SET events = events || ARRAY['tls.expiring', 'tls.alert']
WHERE 'gate.failed' = ANY (events) OR 'scan.failed' = ANY (events);

-- +goose Down
UPDATE notification_channels SET events = array_remove(array_remove(events, 'tls.expiring'), 'tls.alert');
DROP TABLE domain_checks, monitored_domains;
DELETE FROM org_modules WHERE module NOT IN ('repo', 'db');
ALTER TABLE org_modules DROP CONSTRAINT org_modules_module_check;
ALTER TABLE org_modules ADD CONSTRAINT org_modules_module_check CHECK (module IN ('repo', 'db'));
