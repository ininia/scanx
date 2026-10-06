-- name: CreateUser :one
INSERT INTO users (id, email, name, password_hash, is_superadmin, locale)
VALUES ($1, lower(sqlc.arg(email)), $2, $3, $4, $5)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE lower(email) = lower(sqlc.arg(email));

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: ListUsers :many
SELECT * FROM users ORDER BY created_at LIMIT $1 OFFSET $2;

-- name: UpdateUserProfile :exec
UPDATE users SET name = $2, locale = $3 WHERE id = $1;

-- name: UpdateUserPassword :exec
UPDATE users SET password_hash = $2 WHERE id = $1;

-- name: SetUserTOTPSecret :exec
UPDATE users SET totp_secret_enc = $2, totp_nonce = $3, totp_enabled = false WHERE id = $1;

-- name: EnableUserTOTP :exec
UPDATE users SET totp_enabled = true WHERE id = $1 AND totp_secret_enc IS NOT NULL;

-- name: DisableUserTOTP :exec
UPDATE users SET totp_enabled = false, totp_secret_enc = NULL, totp_nonce = NULL WHERE id = $1;

-- name: RecordLoginSuccess :exec
UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now() WHERE id = $1;

-- name: RecordLoginFailure :one
-- Increments the failure counter and locks the account once the threshold is reached.
UPDATE users
SET failed_logins = failed_logins + 1,
    locked_until = CASE WHEN failed_logins + 1 >= sqlc.arg(threshold)::int
                        THEN now() + make_interval(mins => sqlc.arg(lock_minutes)::int)
                        ELSE locked_until END
WHERE id = $1
RETURNING failed_logins, locked_until;
