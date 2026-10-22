-- +goose Up
-- Admin-enforced 2FA (per user, settable on invitations) and one-time
-- password reset links created by organization admins.

ALTER TABLE users ADD COLUMN require_totp boolean NOT NULL DEFAULT false;
ALTER TABLE invitations ADD COLUMN require_totp boolean NOT NULL DEFAULT false;

-- Tokens are stored hashed; the link is shown once to the admin.
CREATE TABLE password_resets (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    org_id     uuid REFERENCES organizations (id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_resets_user_idx ON password_resets (user_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON password_resets TO scanx_app;

-- SBOM: remember which scan the inventory came from, so projects whose
-- SBOM has no components are not backfilled again on every run.
ALTER TABLE projects ADD COLUMN inventory_scan_id uuid;

-- +goose Down
ALTER TABLE projects DROP COLUMN inventory_scan_id;
DROP TABLE password_resets;
ALTER TABLE invitations DROP COLUMN require_totp;
ALTER TABLE users DROP COLUMN require_totp;
