-- +goose Up
-- Faz 0: instance settings, identity and tenancy core.
-- Runtime role `scanx_app` (created by deploy/postgres/init) is NOSUPERUSER and
-- NOBYPASSRLS, so the policies below are enforced for the application.

-- Session-scoped tenant context, set per transaction with
--   SELECT set_config('scanx.org_id', $1, true)
-- Missing/empty settings resolve to NULL, which matches no rows.
CREATE FUNCTION scanx_current_org() RETURNS uuid
    LANGUAGE sql STABLE AS
$$ SELECT NULLIF(current_setting('scanx.org_id', true), '')::uuid $$;

CREATE FUNCTION scanx_current_user() RETURNS uuid
    LANGUAGE sql STABLE AS
$$ SELECT NULLIF(current_setting('scanx.user_id', true), '')::uuid $$;

CREATE FUNCTION scanx_is_superadmin() RETURNS boolean
    LANGUAGE sql STABLE AS
$$ SELECT coalesce(current_setting('scanx.superadmin', true), '') = 'on' $$;

CREATE TABLE instance_settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email           text NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
    name            text NOT NULL DEFAULT '' CHECK (length(name) <= 200),
    password_hash   text NOT NULL,
    totp_secret_enc bytea,
    totp_nonce      bytea,
    totp_enabled    boolean NOT NULL DEFAULT false,
    is_superadmin   boolean NOT NULL DEFAULT false,
    locked_until    timestamptz,
    failed_logins   integer NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_login_at   timestamptz
);
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

CREATE TABLE organizations (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    slug       text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    settings   jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    org_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX memberships_user_idx ON memberships (user_id);

-- Row-level security (defence in depth, spec §5.4).
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY memberships_tenant ON memberships
    USING (org_id = scanx_current_org()
           OR user_id = scanx_current_user()
           OR scanx_is_superadmin())
    WITH CHECK (org_id = scanx_current_org() OR scanx_is_superadmin());

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY organizations_tenant ON organizations
    USING (id = scanx_current_org()
           OR scanx_is_superadmin()
           OR EXISTS (SELECT 1 FROM memberships m
                      WHERE m.org_id = organizations.id AND m.user_id = scanx_current_user()))
    WITH CHECK (id = scanx_current_org() OR scanx_is_superadmin());

-- Runtime privileges. No DDL, no TRUNCATE for the app role.
GRANT SELECT, INSERT, UPDATE, DELETE ON instance_settings, users, organizations, memberships TO scanx_app;
GRANT SELECT ON goose_db_version TO scanx_app;

-- +goose Down
DROP TABLE memberships;
DROP TABLE organizations;
DROP TABLE users;
DROP TABLE instance_settings;
DROP FUNCTION scanx_is_superadmin();
DROP FUNCTION scanx_current_user();
DROP FUNCTION scanx_current_org();
