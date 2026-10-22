-- name: CreateDomain :one
INSERT INTO monitored_domains (id, org_id, host, port, label, schedule, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: ListDomains :many
SELECT * FROM monitored_domains WHERE org_id = $1 ORDER BY cert_not_after NULLS LAST, host;

-- name: CountDomains :one
SELECT count(*) FROM monitored_domains WHERE org_id = $1;

-- name: GetDomain :one
SELECT * FROM monitored_domains WHERE org_id = $1 AND id = $2;

-- name: UpdateDomain :one
UPDATE monitored_domains SET label = $3, schedule = $4, enabled = $5
WHERE org_id = $1 AND id = $2
RETURNING *;

-- name: DeleteDomain :execrows
DELETE FROM monitored_domains WHERE org_id = $1 AND id = $2;

-- name: RequestDomainCheck :exec
UPDATE monitored_domains SET next_check_at = now() WHERE org_id = $1 AND id = $2;

-- name: ClaimDueDomains :many
-- Locks a few due domains for a check (a crashed worker's lock expires).
UPDATE monitored_domains SET locked_until = now() + interval '5 minutes'
WHERE id IN (
    SELECT d.id FROM monitored_domains d
    WHERE d.enabled AND d.next_check_at <= now() AND (d.locked_until IS NULL OR d.locked_until < now())
    ORDER BY d.next_check_at
    LIMIT 5
    FOR UPDATE SKIP LOCKED
)
RETURNING *;

-- name: FinishDomainCheck :exec
UPDATE monitored_domains SET locked_until = NULL, next_check_at = sqlc.arg(next_check_at), last_check_id = sqlc.arg(check_id),
    last_checked_at = now(), last_score = sqlc.arg(score), last_grade = sqlc.arg(grade), last_error = sqlc.arg(last_error),
    cert_not_after = sqlc.arg(cert_not_after), cert_issuer = sqlc.arg(cert_issuer), alerted_days = sqlc.arg(alerted_days)
WHERE id = sqlc.arg(id);

-- name: InsertDomainCheck :exec
INSERT INTO domain_checks (id, org_id, domain_id, score, grade, counts, result) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ListDomainChecks :many
SELECT id, checked_at, score, grade, counts FROM domain_checks
WHERE org_id = $1 AND domain_id = $2 ORDER BY checked_at DESC LIMIT $3;

-- name: GetDomainCheck :one
SELECT * FROM domain_checks WHERE org_id = $1 AND id = $2;

-- name: LastDomainCheck :one
SELECT * FROM domain_checks WHERE domain_id = $1 ORDER BY checked_at DESC LIMIT 1;

-- name: PruneDomainChecks :execrows
-- Keeps a year of history.
DELETE FROM domain_checks WHERE checked_at < now() - interval '365 days';
