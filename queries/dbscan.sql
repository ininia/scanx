-- ---------- module entitlements ----------

-- name: ListOrgModules :many
SELECT * FROM org_modules WHERE org_id = $1 ORDER BY module;

-- name: ListAllOrgModules :many
SELECT * FROM org_modules ORDER BY org_id, module;

-- name: UpsertOrgModule :exec
INSERT INTO org_modules (org_id, module, enabled, settings, updated_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (org_id, module) DO UPDATE SET enabled = EXCLUDED.enabled, settings = EXCLUDED.settings, updated_at = now();

-- ---------- rule profile ----------

-- name: GetDBProfile :one
SELECT * FROM db_profiles WHERE org_id = $1;

-- name: UpsertDBProfile :exec
INSERT INTO db_profiles (org_id, profile, updated_by, updated_at) VALUES ($1, $2, $3, now())
ON CONFLICT (org_id) DO UPDATE SET profile = EXCLUDED.profile, updated_by = EXCLUDED.updated_by, updated_at = now();

-- ---------- connections ----------

-- name: CreateDBConnection :one
INSERT INTO db_connections (id, org_id, name, engine, host, port, database_name, username, password_enc, password_nonce,
    tls_mode, schedule, schedule_hour, schedule_weekday, next_run_at, exclude, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
RETURNING *;

-- name: ListDBConnections :many
SELECT * FROM db_connections WHERE org_id = $1 ORDER BY name;

-- name: CountDBConnections :one
SELECT count(*) FROM db_connections WHERE org_id = $1;

-- name: GetDBConnection :one
SELECT * FROM db_connections WHERE org_id = $1 AND id = $2;

-- name: UpdateDBConnection :one
-- Settings that do not touch the credential's destination.
UPDATE db_connections SET name = $3, tls_mode = $4, schedule = $5, schedule_hour = $6, schedule_weekday = $7,
    next_run_at = $8, exclude = $9, updated_at = now()
WHERE org_id = $1 AND id = $2
RETURNING *;

-- name: SetDBConnectionTarget :one
-- New destination or credential: the account is checked again before use.
UPDATE db_connections SET engine = $3, host = $4, port = $5, database_name = $6, username = $7,
    password_enc = $8, password_nonce = $9, status = 'pending', verify_result = '{}'::jsonb, verified_at = NULL,
    updated_at = now()
WHERE org_id = $1 AND id = $2
RETURNING *;

-- name: RequestDBVerify :exec
UPDATE db_connections SET status = 'pending', updated_at = now()
WHERE org_id = $1 AND id = $2 AND password_enc IS NOT NULL AND status <> 'verifying';

-- name: DeleteDBConnection :execrows
DELETE FROM db_connections WHERE org_id = $1 AND id = $2;

-- name: ClaimDBVerify :one
UPDATE db_connections SET status = 'verifying', verify_locked_by = sqlc.arg(worker), verify_locked_until = sqlc.arg(locked_until)
WHERE id = (
    SELECT c.id FROM db_connections c
    WHERE (c.status = 'pending' OR (c.status = 'verifying' AND c.verify_locked_until < now())) AND c.password_enc IS NOT NULL
    ORDER BY c.updated_at
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING *;

-- name: FinishDBVerify :exec
-- A failed read-only check wipes the stored password (wipe = true).
UPDATE db_connections SET status = sqlc.arg(status), verify_result = sqlc.arg(verify_result), verified_at = now(),
    verify_locked_by = '', verify_locked_until = NULL,
    password_enc = CASE WHEN sqlc.arg(wipe)::boolean THEN NULL ELSE password_enc END,
    password_nonce = CASE WHEN sqlc.arg(wipe)::boolean THEN NULL ELSE password_nonce END
WHERE id = sqlc.arg(id);

-- name: DueDBSchedules :many
SELECT * FROM db_connections
WHERE schedule <> 'off' AND status = 'ready' AND next_run_at IS NOT NULL AND next_run_at <= now()
ORDER BY next_run_at
LIMIT 20
FOR UPDATE SKIP LOCKED;

-- name: SetDBNextRun :exec
UPDATE db_connections SET next_run_at = $2 WHERE id = $1;

-- ---------- scans ----------

-- name: CreateDBScan :one
-- ON CONFLICT: a scan of this connection is already queued or running.
INSERT INTO db_scans (id, org_id, connection_id, trigger, triggered_by)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (connection_id) WHERE status IN ('queued', 'running') DO NOTHING
RETURNING *;

-- name: ActiveDBScan :one
SELECT * FROM db_scans WHERE connection_id = $1 AND status IN ('queued', 'running') LIMIT 1;

-- name: ClaimDBScan :one
UPDATE db_scans SET status = 'running', locked_by = sqlc.arg(worker), locked_until = sqlc.arg(locked_until),
    started_at = coalesce(started_at, now())
WHERE id = (
    SELECT s.id FROM db_scans s
    WHERE s.status = 'queued' OR (s.status = 'running' AND s.locked_until < now() - interval '10 minutes')
    ORDER BY s.queued_at
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING *;

-- name: ExtendDBScanLock :exec
UPDATE db_scans SET locked_until = $2 WHERE id = $1 AND status = 'running';

-- name: SetDBScanLog :exec
UPDATE db_scans SET log = $2 WHERE id = $1;

-- name: FinishDBScan :exec
UPDATE db_scans SET status = sqlc.arg(status), status_reason = sqlc.arg(status_reason), score = sqlc.arg(score),
    grade = sqlc.arg(grade), gate_result = sqlc.arg(gate_result), counts = sqlc.arg(counts), summary = sqlc.arg(summary),
    read_only = sqlc.arg(read_only), snapshot_gz = sqlc.arg(snapshot_gz), new_findings = sqlc.arg(new_findings),
    fixed_findings = sqlc.arg(fixed_findings), log = sqlc.arg(log), finished_at = now(), locked_by = '', locked_until = NULL
WHERE id = sqlc.arg(id);

-- name: CancelDBScan :execrows
UPDATE db_scans SET status = 'canceled', status_reason = 'Canceled by user.', finished_at = now()
WHERE org_id = $1 AND id = $2 AND status = 'queued';

-- name: FailStaleDBScans :execrows
UPDATE db_scans SET status = 'failed', status_reason = 'The worker stopped responding during this scan.', finished_at = now()
WHERE status = 'running' AND locked_until < now() - interval '30 minutes';

-- name: GetDBScan :one
SELECT * FROM db_scans WHERE org_id = $1 AND id = $2;

-- name: ListDBScans :many
SELECT id, org_id, connection_id, trigger, status, status_reason, score, grade, gate_result, counts,
       new_findings, fixed_findings, queued_at, started_at, finished_at
FROM db_scans WHERE org_id = $1 AND connection_id = $2
ORDER BY queued_at DESC LIMIT $3;

-- name: LastDBScanPerConnection :many
SELECT DISTINCT ON (connection_id) connection_id, id, status, score, grade, gate_result, counts, queued_at, finished_at
FROM db_scans WHERE org_id = $1
ORDER BY connection_id, queued_at DESC;

-- name: PreviousDBScanFingerprints :many
SELECT f.fingerprint FROM db_findings f
WHERE f.scan_id = (
    SELECT s.id FROM db_scans s
    WHERE s.connection_id = $1 AND s.status = 'completed' AND s.id <> $2
    ORDER BY s.finished_at DESC LIMIT 1
);

-- name: InsertDBFinding :exec
-- (COPY is not available on tables with row-level security.)
INSERT INTO db_findings (id, org_id, scan_id, connection_id, rule_id, category, severity, object_type, object, params,
    details, fingerprint, is_new)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);

-- name: ListDBFindings :many
SELECT * FROM db_findings WHERE org_id = $1 AND scan_id = $2;
