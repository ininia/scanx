-- name: SetUserRequireTOTP :exec
UPDATE users SET require_totp = $2 WHERE id = $1;

-- name: GetInvitationRequireTOTP :one
SELECT require_totp FROM invitations WHERE id = $1;

-- name: SetInvitationRequireTOTP :exec
UPDATE invitations SET require_totp = $2 WHERE id = $1;

-- name: CountUserMemberships :one
SELECT count(*) FROM memberships WHERE user_id = $1;

-- name: InvalidatePasswordResets :exec
UPDATE password_resets SET used_at = now() WHERE user_id = $1 AND used_at IS NULL;

-- name: CreatePasswordReset :exec
INSERT INTO password_resets (id, user_id, org_id, token_hash, created_by, expires_at) VALUES ($1, $2, $3, $4, $5, $6);

-- name: LookupPasswordReset :one
SELECT r.id, r.user_id, r.org_id, r.expires_at, u.email, u.name
FROM password_resets r JOIN users u ON u.id = r.user_id
WHERE r.token_hash = $1 AND r.used_at IS NULL AND r.expires_at > now();

-- name: UsePasswordReset :execrows
UPDATE password_resets SET used_at = now() WHERE id = $1 AND used_at IS NULL AND expires_at > now();

-- name: ResetUserPassword :exec
-- New password from a reset link: also lifts a login lockout.
UPDATE users SET password_hash = $2, failed_logins = 0, locked_until = NULL WHERE id = $1;
