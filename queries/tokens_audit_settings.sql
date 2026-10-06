-- name: CreateAPIToken :exec
INSERT INTO api_tokens (id, org_id, user_id, project_id, name, token_prefix, token_hash, scopes, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ListUserAPITokens :many
SELECT id, org_id, name, token_prefix, scopes, last_used_at, expires_at, created_at
FROM api_tokens WHERE org_id = $1 AND user_id = $2 AND revoked_at IS NULL ORDER BY created_at DESC;

-- name: RevokeUserAPIToken :execrows
UPDATE api_tokens SET revoked_at = now() WHERE org_id = $1 AND user_id = $2 AND id = $3 AND revoked_at IS NULL;

-- name: LookupAPIToken :one
-- Nullable columns are coalesced to zero values (zero = absent).
SELECT l.id::uuid AS id, l.org_id::uuid AS org_id,
       coalesce(l.user_id, '00000000-0000-0000-0000-000000000000'::uuid)::uuid AS user_id, coalesce(l.project_id, '00000000-0000-0000-0000-000000000000'::uuid)::uuid AS project_id,
       l.scopes::text[] AS scopes,
       coalesce(l.expires_at, '0001-01-01 00:00:00+00'::timestamptz)::timestamptz AS expires_at,
       coalesce(l.revoked_at, '0001-01-01 00:00:00+00'::timestamptz)::timestamptz AS revoked_at
FROM scanx_lookup_api_token(sqlc.arg(token_hash)::bytea) AS l;

-- name: TouchAPIToken :exec
UPDATE api_tokens SET last_used_at = now() WHERE id = $1;

-- name: InsertAuditLog :exec
INSERT INTO audit_logs (id, org_id, user_id, action, target_type, target_id, ip, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: ListAuditLogs :many
SELECT a.id, a.org_id, a.user_id, a.action, a.target_type, a.target_id, a.ip, a.metadata, a.created_at,
       coalesce(u.email, '') AS user_email
FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id
WHERE a.org_id = $1
ORDER BY a.created_at DESC LIMIT $2 OFFSET $3;

-- name: GetSetting :one
SELECT value FROM instance_settings WHERE key = $1;

-- name: UpsertSetting :exec
INSERT INTO instance_settings (key, value, updated_at) VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();

-- name: LockSetup :exec
-- Serializes first-admin creation across concurrent requests.
SELECT pg_advisory_xact_lock(726200);
