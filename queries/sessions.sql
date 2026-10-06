-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, token_hash, mfa_pending, active_org_id, ip, user_agent, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetSessionByHash :one
SELECT s.id, s.user_id, s.mfa_pending, s.active_org_id, s.created_at, s.last_seen_at, s.expires_at,
       u.email, u.name, u.is_superadmin, u.totp_enabled, u.locale, u.locked_until
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.token_hash = $1 AND s.expires_at > now();

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = now(), expires_at = sqlc.arg(expires_at) WHERE id = $1;

-- name: SetSessionActiveOrg :exec
UPDATE sessions SET active_org_id = $2 WHERE id = $1;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = $1;

-- name: DeleteUserSessionsExcept :exec
DELETE FROM sessions WHERE user_id = $1 AND id <> sqlc.arg(keep_id);

-- name: DeleteUserSession :execrows
DELETE FROM sessions WHERE user_id = $1 AND id = sqlc.arg(session_id);

-- name: ListUserSessions :many
SELECT id, ip, user_agent, created_at, last_seen_at, mfa_pending
FROM sessions WHERE user_id = $1 AND expires_at > now() ORDER BY last_seen_at DESC;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE expires_at <= now();
