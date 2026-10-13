-- name: DashboardCounts :one
-- Current numbers and their values one period ago, for the trend arrows.
-- "Open a week ago" = created before then and either still open or changed
-- status since (fixed/triaged within the week).
SELECT
    (SELECT count(*) FROM projects p WHERE p.org_id = $1 AND p.archived_at IS NULL)::bigint AS projects_now,
    (SELECT count(*) FROM projects p WHERE p.org_id = $1 AND p.archived_at IS NULL
        AND p.created_at < now() - interval '30 days')::bigint AS projects_before,
    (SELECT count(*) FROM memberships m WHERE m.org_id = $1)::bigint AS members_now,
    (SELECT count(*) FROM memberships m WHERE m.org_id = $1
        AND m.created_at < now() - interval '30 days')::bigint AS members_before,
    (SELECT count(*) FROM issues i WHERE i.org_id = $1 AND i.severity = 'critical' AND i.status = 'open')::bigint AS critical_now,
    (SELECT count(*) FROM issues i WHERE i.org_id = $1 AND i.severity = 'critical'
        AND i.created_at < now() - interval '7 days'
        AND (i.status = 'open' OR i.updated_at > now() - interval '7 days'))::bigint AS critical_before,
    (SELECT count(*) FROM issues i WHERE i.org_id = $1 AND i.severity = 'high' AND i.status = 'open')::bigint AS high_now,
    (SELECT count(*) FROM issues i WHERE i.org_id = $1 AND i.severity = 'high'
        AND i.created_at < now() - interval '7 days'
        AND (i.status = 'open' OR i.updated_at > now() - interval '7 days'))::bigint AS high_before;

-- name: DashboardDaily :many
-- Last 14 days, one row per day, for the sparklines.
SELECT d.day::date AS day,
    (SELECT count(*) FROM scans s WHERE s.org_id = $1 AND s.queued_at >= d.day AND s.queued_at < d.day + interval '1 day')::bigint AS scans,
    (SELECT count(*) FROM memberships m WHERE m.org_id = $1 AND m.created_at < d.day + interval '1 day')::bigint AS members,
    (SELECT count(*) FROM issues i WHERE i.org_id = $1 AND i.severity = 'critical'
        AND i.created_at >= d.day AND i.created_at < d.day + interval '1 day')::bigint AS new_critical,
    (SELECT count(*) FROM issues i WHERE i.org_id = $1 AND i.severity = 'high'
        AND i.created_at >= d.day AND i.created_at < d.day + interval '1 day')::bigint AS new_high
FROM generate_series(date_trunc('day', now()) - interval '13 days', date_trunc('day', now()), interval '1 day') AS d(day)
ORDER BY d.day;

-- name: RecentProblemScans :many
-- Failed scans and failed quality gates of the last 7 days (bell menu).
SELECT s.id, s.status, s.gate_result, s.branch, s.queued_at, p.name AS project_name
FROM scans s JOIN projects p ON p.id = s.project_id
WHERE s.org_id = $1 AND s.queued_at > now() - interval '7 days'
  AND (s.status = 'failed' OR s.gate_result = 'fail')
ORDER BY s.queued_at DESC
LIMIT 6;

-- name: SearchProjects :many
SELECT * FROM projects
WHERE org_id = $1 AND (name ILIKE sqlc.arg(q)::text OR slug ILIKE sqlc.arg(q)::text OR repo_url ILIKE sqlc.arg(q)::text)
ORDER BY name LIMIT 20;

-- name: SearchIssues :many
SELECT i.id, i.severity, i.title, i.file, i.start_line, i.status, i.category, p.name AS project_name
FROM issues i JOIN projects p ON p.id = i.project_id
WHERE i.org_id = $1 AND (i.title ILIKE sqlc.arg(q)::text OR i.file ILIKE sqlc.arg(q)::text OR i.rule_id ILIKE sqlc.arg(q)::text)
ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, i.updated_at DESC
LIMIT 30;

-- name: SearchScans :many
SELECT s.id, s.status, s.gate_result, s.branch, s.commit_sha, s.commit_message, s.queued_at, p.name AS project_name
FROM scans s JOIN projects p ON p.id = s.project_id
WHERE s.org_id = $1 AND (s.commit_sha ILIKE sqlc.arg(prefix)::text OR s.branch ILIKE sqlc.arg(q)::text OR s.commit_message ILIKE sqlc.arg(q)::text)
ORDER BY s.queued_at DESC LIMIT 15;
