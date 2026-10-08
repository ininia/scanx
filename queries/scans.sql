-- ---------- deploy keys ----------

-- name: CreateSSHKey :exec
INSERT INTO ssh_keys (id, org_id, project_id, public_key, fingerprint, private_key_enc, nonce)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetActiveSSHKey :one
SELECT * FROM ssh_keys WHERE org_id = $1 AND project_id = $2 AND status = 'active';

-- name: RetireSSHKeys :exec
UPDATE ssh_keys SET status = 'retiring', retired_at = now()
WHERE org_id = $1 AND project_id = $2 AND status = 'active';

-- name: DeleteOldSSHKeys :execrows
DELETE FROM ssh_keys WHERE status = 'retiring' AND retired_at < now() - interval '7 days';

-- ---------- project scan settings ----------

-- name: SetWebhookSecret :exec
UPDATE projects SET webhook_secret_enc = $3, webhook_secret_nonce = $4, updated_at = now()
WHERE org_id = $1 AND id = $2;

-- name: UpdateProjectScanSettings :exec
UPDATE projects SET fail_on = $3, scan_history = $4, updated_at = now() WHERE org_id = $1 AND id = $2;

-- name: LookupWebhookProject :one
SELECT l.id::uuid AS id, l.org_id::uuid AS org_id, l.provider::text AS provider, l.branches::text[] AS branches,
       coalesce(l.webhook_secret_enc, ''::bytea)::bytea AS webhook_secret_enc,
       coalesce(l.webhook_secret_nonce, ''::bytea)::bytea AS webhook_secret_nonce,
       l.archived::bool AS archived
FROM scanx_lookup_webhook_project(sqlc.arg(project_id)::uuid) AS l;

-- name: InsertWebhookDelivery :one
INSERT INTO webhook_deliveries (id, org_id, project_id, provider, delivery_id, event, result)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (provider, delivery_id) DO NOTHING
RETURNING id;

-- ---------- jobs ----------

-- name: EnqueueJob :exec
INSERT INTO jobs (id, org_id, kind, project_id, scan_id) VALUES ($1, $2, $3, $4, $5);

-- name: ClaimJob :one
-- Takes the oldest queued job, or a running job whose worker died (lock
-- expired) if it has attempts left.
UPDATE jobs SET status = 'running', locked_by = sqlc.arg(worker), locked_until = sqlc.arg(locked_until),
    attempts = attempts + 1, started_at = coalesce(started_at, now())
WHERE id = (
    SELECT j.id FROM jobs j
    WHERE j.status = 'queued' OR (j.status = 'running' AND j.locked_until < now() AND j.attempts < 3)
    ORDER BY j.created_at
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING *;

-- name: ExtendJobLock :exec
UPDATE jobs SET locked_until = $2 WHERE id = $1 AND status = 'running';

-- name: FinishJob :exec
UPDATE jobs SET status = $2, result = $3, error = $4, finished_at = now(), locked_until = NULL WHERE id = $1;

-- name: FailStaleJobs :many
UPDATE jobs SET status = 'failed', error = 'worker stopped responding', finished_at = now()
WHERE status = 'running' AND locked_until < now() AND attempts >= 3
RETURNING id, scan_id;

-- name: GetJob :one
SELECT * FROM jobs WHERE org_id = $1 AND id = $2;

-- name: CountQueuedJobs :one
SELECT count(*) FROM jobs WHERE status IN ('queued', 'running');

-- ---------- scans ----------

-- name: CreateScan :one
INSERT INTO scans (id, org_id, project_id, trigger, triggered_by, branch, commit_sha, commit_message, commit_author)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (project_id, branch, commit_sha)
    WHERE status IN ('queued', 'cloning', 'scanning', 'reporting') AND commit_sha <> '' DO NOTHING
RETURNING *;

-- name: ActiveManualScan :one
SELECT * FROM scans WHERE org_id = $1 AND project_id = $2 AND branch = $3 AND status = 'queued' AND commit_sha = ''
LIMIT 1;

-- name: GetScan :one
SELECT * FROM scans WHERE org_id = $1 AND id = $2;

-- name: GetScanByID :one
SELECT * FROM scans WHERE id = $1;

-- name: ListProjectScans :many
SELECT * FROM scans WHERE org_id = $1 AND project_id = $2 ORDER BY queued_at DESC LIMIT $3;

-- name: ListOrgScans :many
SELECT s.*, p.name AS project_name, p.slug AS project_slug
FROM scans s JOIN projects p ON p.id = s.project_id
WHERE s.org_id = $1 ORDER BY s.queued_at DESC LIMIT $2;

-- name: SetScanStatus :exec
UPDATE scans SET status = $2, status_reason = $3,
    started_at = CASE WHEN $2 = 'cloning' THEN coalesce(started_at, now()) ELSE started_at END
WHERE id = $1;

-- name: SetScanCommit :exec
UPDATE scans SET commit_sha = $2, commit_message = $3, commit_author = $4 WHERE id = $1;

-- name: FinishScan :exec
UPDATE scans SET status = $2, status_reason = $3, partial = $4, summary = $5, gate_result = $6, score = $7,
    new_issues = $8, fixed_issues = $9, finished_at = now(), cleaned_at = now()
WHERE id = $1;

-- name: CancelScan :execrows
UPDATE scans SET status = 'canceled', finished_at = now()
WHERE org_id = $1 AND id = $2 AND status IN ('queued', 'cloning', 'scanning', 'reporting');

-- name: IsScanCanceled :one
SELECT status = 'canceled' FROM scans WHERE id = $1;

-- name: InsertScanTool :exec
INSERT INTO scan_tools (id, org_id, scan_id, tool_id, name, tool_version, status, duration_ms, findings_count, error)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: ListScanTools :many
SELECT * FROM scan_tools WHERE org_id = $1 AND scan_id = $2 ORDER BY tool_id;

-- name: LastScanPerProject :many
SELECT DISTINCT ON (s.project_id) s.project_id, s.id, s.status, s.gate_result, s.score, s.finished_at, s.summary
FROM scans s WHERE s.org_id = $1 ORDER BY s.project_id, s.queued_at DESC;

-- ---------- issues ----------

-- name: UpsertIssue :one
-- Re-opens a previously fixed issue that reappears; user decisions
-- (false_positive, accepted_risk, wont_fix) are kept.
INSERT INTO issues (id, org_id, project_id, fingerprint, category, severity, title, rule_id, file, start_line,
                    cwe, cve, sources, detail, first_seen_scan_id, last_seen_scan_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $15)
ON CONFLICT (project_id, fingerprint) DO UPDATE SET
    severity = EXCLUDED.severity, title = EXCLUDED.title, rule_id = EXCLUDED.rule_id, file = EXCLUDED.file,
    start_line = EXCLUDED.start_line, cwe = EXCLUDED.cwe, cve = EXCLUDED.cve, sources = EXCLUDED.sources,
    detail = EXCLUDED.detail, last_seen_scan_id = EXCLUDED.last_seen_scan_id,
    status = CASE WHEN issues.status = 'fixed' THEN 'open' ELSE issues.status END,
    fixed_in_scan_id = CASE WHEN issues.status = 'fixed' THEN NULL ELSE issues.fixed_in_scan_id END,
    updated_at = now()
RETURNING id, (xmax = 0) AS inserted, status;

-- name: InsertScanIssue :exec
INSERT INTO scan_issues (scan_id, issue_id, org_id, is_new) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING;

-- name: MarkMissingIssuesFixed :execrows
UPDATE issues SET status = 'fixed', fixed_in_scan_id = sqlc.arg(scan_id)::uuid, updated_at = now()
WHERE project_id = sqlc.arg(project_id)::uuid AND status = 'open'
  AND id NOT IN (SELECT issue_id FROM scan_issues WHERE scan_id = sqlc.arg(scan_id)::uuid);

-- name: ListScanIssues :many
SELECT i.*, si.is_new FROM scan_issues si JOIN issues i ON i.id = si.issue_id
WHERE si.org_id = $1 AND si.scan_id = $2
ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
         i.file, i.start_line;

-- name: ListProjectIssues :many
SELECT * FROM issues WHERE org_id = $1 AND project_id = $2 AND (sqlc.arg(status)::text = '' OR status = sqlc.arg(status)::text)
ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
         file, start_line
LIMIT 500;

-- name: GetIssue :one
SELECT * FROM issues WHERE org_id = $1 AND id = $2;

-- name: UpdateIssueStatus :exec
UPDATE issues SET status = $3, status_reason = $4, updated_at = now() WHERE org_id = $1 AND id = $2;

-- name: InsertIssueEvent :exec
INSERT INTO issue_events (id, org_id, issue_id, user_id, kind, from_value, to_value, comment)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: ListIssueEvents :many
SELECT e.*, coalesce(u.email, '') AS user_email FROM issue_events e LEFT JOIN users u ON u.id = e.user_id
WHERE e.org_id = $1 AND e.issue_id = $2 ORDER BY e.created_at;

-- name: CountOpenIssues :many
SELECT severity, count(*) AS n FROM issues WHERE org_id = $1 AND status = 'open' GROUP BY severity;

-- name: CountOpenIssuesByProject :many
SELECT project_id, severity, count(*) AS n FROM issues WHERE org_id = $1 AND status = 'open'
GROUP BY project_id, severity;

-- ---------- reports ----------

-- name: InsertReport :exec
INSERT INTO reports (id, org_id, scan_id, format, content_gz) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (scan_id, format) DO UPDATE SET content_gz = EXCLUDED.content_gz;

-- name: GetReport :one
SELECT content_gz FROM reports WHERE org_id = $1 AND scan_id = $2 AND format = $3;

-- ---------- notifications ----------

-- name: CreateNotificationChannel :exec
INSERT INTO notification_channels (id, org_id, kind, name, target_enc, nonce, events)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ListNotificationChannels :many
SELECT * FROM notification_channels WHERE org_id = $1 ORDER BY created_at;

-- name: GetNotificationChannel :one
SELECT * FROM notification_channels WHERE org_id = $1 AND id = $2;

-- name: DeleteNotificationChannel :execrows
DELETE FROM notification_channels WHERE org_id = $1 AND id = $2;
