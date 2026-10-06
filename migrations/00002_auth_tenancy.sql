-- +goose Up
-- Faz 2: sessions, API tokens, invitations, projects, audit log.
-- Every org-scoped table has FORCE ROW LEVEL SECURITY bound to scanx.org_id.

ALTER TABLE users ADD COLUMN locale text NOT NULL DEFAULT '' CHECK (locale IN ('', 'tr', 'en'));

CREATE TABLE sessions (
    id            uuid PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash    bytea NOT NULL UNIQUE,
    mfa_pending   boolean NOT NULL DEFAULT false,
    active_org_id uuid REFERENCES organizations (id) ON DELETE SET NULL,
    ip            text NOT NULL DEFAULT '',
    user_agent    text NOT NULL DEFAULT '' CHECK (length(user_agent) <= 512),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

CREATE TABLE projects (
    id            uuid PRIMARY KEY,
    org_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    slug          text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    repo_url      text NOT NULL CHECK (length(repo_url) BETWEEN 1 AND 1000),
    provider      text NOT NULL CHECK (provider IN ('github', 'gitlab', 'gitea', 'bitbucket', 'generic')),
    auth_mode     text NOT NULL DEFAULT 'deploy_key' CHECK (auth_mode IN ('deploy_key', 'instance_key', 'https_token')),
    branches      text[] NOT NULL DEFAULT '{main,master}',
    settings      jsonb NOT NULL DEFAULT '{}'::jsonb,
    schedule_cron text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    archived_at   timestamptz,
    UNIQUE (org_id, slug)
);

CREATE TABLE invitations (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email       text NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
    role        text NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    token_hash  bytea NOT NULL UNIQUE,
    invited_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    expires_at  timestamptz NOT NULL,
    accepted_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX invitations_org_idx ON invitations (org_id);

CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id      uuid REFERENCES users (id) ON DELETE CASCADE,
    project_id   uuid REFERENCES projects (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    token_prefix text NOT NULL,
    token_hash   bytea NOT NULL UNIQUE,
    scopes       text[] NOT NULL,
    last_used_at timestamptz,
    expires_at   timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CHECK (user_id IS NOT NULL OR project_id IS NOT NULL)
);
CREATE INDEX api_tokens_org_idx ON api_tokens (org_id);

CREATE TABLE audit_logs (
    id          uuid PRIMARY KEY,
    org_id      uuid REFERENCES organizations (id) ON DELETE CASCADE,
    user_id     uuid REFERENCES users (id) ON DELETE SET NULL,
    action      text NOT NULL,
    target_type text NOT NULL DEFAULT '',
    target_id   text NOT NULL DEFAULT '',
    ip          text NOT NULL DEFAULT '',
    metadata    jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_org_created_idx ON audit_logs (org_id, created_at DESC);

-- Row-level security.
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
CREATE POLICY projects_tenant ON projects
    USING (org_id = scanx_current_org() OR scanx_is_superadmin())
    WITH CHECK (org_id = scanx_current_org() OR scanx_is_superadmin());

ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY invitations_tenant ON invitations
    USING (org_id = scanx_current_org() OR scanx_is_superadmin())
    WITH CHECK (org_id = scanx_current_org() OR scanx_is_superadmin());

ALTER TABLE api_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY api_tokens_tenant ON api_tokens
    USING (org_id = scanx_current_org() OR scanx_is_superadmin())
    WITH CHECK (org_id = scanx_current_org() OR scanx_is_superadmin());

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_logs_read ON audit_logs FOR SELECT
    USING (org_id = scanx_current_org() OR scanx_is_superadmin());
CREATE POLICY audit_logs_insert ON audit_logs FOR INSERT
    WITH CHECK (org_id IS NULL OR org_id = scanx_current_org() OR scanx_is_superadmin());

-- Narrow lookups that must work before a tenant is known. They run with the
-- owner's rights, take only a hash, and return a single row's essentials.
-- +goose StatementBegin
CREATE FUNCTION scanx_lookup_api_token(p_hash bytea)
    RETURNS TABLE (id uuid, org_id uuid, user_id uuid, project_id uuid, scopes text[],
                   expires_at timestamptz, revoked_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
$$ SELECT t.id, t.org_id, t.user_id, t.project_id, t.scopes, t.expires_at, t.revoked_at
   FROM api_tokens t WHERE t.token_hash = p_hash $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION scanx_lookup_invitation(p_hash bytea)
    RETURNS TABLE (id uuid, org_id uuid, email text, role text, expires_at timestamptz,
                   accepted_at timestamptz, org_name text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
$$ SELECT i.id, i.org_id, i.email, i.role, i.expires_at, i.accepted_at, o.name
   FROM invitations i JOIN organizations o ON o.id = i.org_id WHERE i.token_hash = p_hash $$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION scanx_lookup_api_token(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION scanx_lookup_invitation(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION scanx_lookup_api_token(bytea) TO scanx_app;
GRANT EXECUTE ON FUNCTION scanx_lookup_invitation(bytea) TO scanx_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, projects, invitations, api_tokens TO scanx_app;
-- The audit log is append-only for the application.
GRANT SELECT, INSERT ON audit_logs TO scanx_app;

-- +goose Down
DROP FUNCTION scanx_lookup_invitation(bytea);
DROP FUNCTION scanx_lookup_api_token(bytea);
DROP TABLE audit_logs;
DROP TABLE api_tokens;
DROP TABLE invitations;
DROP TABLE projects;
DROP TABLE sessions;
ALTER TABLE users DROP COLUMN locale;
