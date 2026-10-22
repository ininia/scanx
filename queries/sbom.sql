-- ---------- inventory ----------

-- name: DeleteProjectComponents :exec
DELETE FROM sbom_components WHERE project_id = $1;

-- name: InsertComponent :exec
INSERT INTO sbom_components (id, org_id, project_id, scan_id, ecosystem, name, version, purl, licenses)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (project_id, purl) DO NOTHING;

-- name: AllComponents :many
-- The whole inventory (monitor run, superadmin scope).
SELECT org_id, project_id, ecosystem, name, version FROM sbom_components;

-- name: ProjectsWithoutInventory :many
-- Latest complete scan with an SBOM of projects that have no inventory yet.
SELECT DISTINCT ON (s.project_id) s.project_id, s.id AS scan_id, s.org_id
FROM scans s
JOIN projects p ON p.id = s.project_id
JOIN reports r ON r.scan_id = s.id AND r.format = 'sbom'
WHERE s.status = 'completed' AND s.scope = 'full' AND NOT s.partial AND p.archived_at IS NULL
  AND p.inventory_scan_id IS NULL
  AND NOT EXISTS (SELECT 1 FROM sbom_components c WHERE c.project_id = s.project_id)
ORDER BY s.project_id, s.finished_at DESC;

-- name: SetProjectInventoryScan :exec
UPDATE projects SET inventory_scan_id = $2 WHERE id = $1;

-- name: GetSBOMReport :one
SELECT content_gz FROM reports WHERE scan_id = $1 AND format = 'sbom';

-- name: InventoryStats :one
SELECT count(*)::bigint AS components, count(DISTINCT project_id)::bigint AS projects,
       count(DISTINCT (ecosystem, name))::bigint AS packages
FROM sbom_components WHERE org_id = $1;

-- name: SearchComponents :many
SELECT c.ecosystem, c.name, c.version, c.licenses, p.name AS project_name, p.slug AS project_slug
FROM sbom_components c JOIN projects p ON p.id = c.project_id
WHERE c.org_id = sqlc.arg(org_id) AND (sqlc.arg(q)::text = '' OR c.name ILIKE sqlc.arg(q)::text OR c.purl ILIKE sqlc.arg(q)::text)
  AND (sqlc.arg(lic)::text = '' OR sqlc.arg(lic)::text = ANY (CASE WHEN c.licenses = '{}' THEN ARRAY['(unknown)'] ELSE c.licenses END))
ORDER BY c.name, c.version, p.name
LIMIT 300;

-- name: TopPackages :many
SELECT ecosystem, name, count(DISTINCT project_id)::bigint AS projects, count(DISTINCT version)::bigint AS versions
FROM sbom_components WHERE org_id = $1
GROUP BY ecosystem, name ORDER BY projects DESC, name LIMIT 50;

-- name: LicenseCounts :many
SELECT lic::text AS license, count(*)::bigint AS components, count(DISTINCT project_id)::bigint AS projects
FROM sbom_components, unnest(CASE WHEN licenses = '{}' THEN ARRAY['(unknown)'] ELSE licenses END) AS lic
WHERE org_id = $1
GROUP BY lic ORDER BY components DESC LIMIT 100;

-- name: AllInventory :many
SELECT c.ecosystem, c.name, c.version, c.purl, c.licenses, p.name AS project_name
FROM sbom_components c JOIN projects p ON p.id = c.project_id
WHERE c.org_id = $1 ORDER BY p.name, c.ecosystem, c.name;

-- ---------- matches ----------

-- name: UpsertVulnMatch :one
INSERT INTO vuln_matches (id, org_id, project_id, ecosystem, name, version, vuln_id, cve, aliases, severity, summary,
    fixed_version, published)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (project_id, ecosystem, name, version, vuln_id) DO UPDATE SET
    last_seen_at = now(), resolved_at = NULL, severity = EXCLUDED.severity, summary = EXCLUDED.summary,
    fixed_version = EXCLUDED.fixed_version, cve = EXCLUDED.cve, aliases = EXCLUDED.aliases
RETURNING (xmax = 0) AS inserted, id;

-- name: ResolveStaleMatches :execrows
-- Matches not seen in a run are resolved (package upgraded or removed).
UPDATE vuln_matches SET resolved_at = now() WHERE resolved_at IS NULL AND last_seen_at < sqlc.arg(run_started);

-- name: UnnotifiedMatches :many
SELECT m.*, p.name AS project_name FROM vuln_matches m JOIN projects p ON p.id = m.project_id
WHERE NOT m.notified AND m.resolved_at IS NULL ORDER BY m.org_id;

-- name: MarkMatchesNotified :exec
UPDATE vuln_matches SET notified = true WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: ListOpenMatches :many
SELECT m.*, p.name AS project_name, p.slug AS project_slug FROM vuln_matches m JOIN projects p ON p.id = m.project_id
WHERE m.org_id = $1 AND m.resolved_at IS NULL
ORDER BY CASE m.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, m.first_seen_at DESC
LIMIT 1000;

-- name: MatchCounts :many
SELECT severity, count(*)::bigint AS n FROM vuln_matches WHERE org_id = $1 AND resolved_at IS NULL GROUP BY severity;

-- name: RecentlyResolved :many
SELECT m.*, p.name AS project_name FROM vuln_matches m JOIN projects p ON p.id = m.project_id
WHERE m.org_id = $1 AND m.resolved_at > now() - interval '30 days'
ORDER BY m.resolved_at DESC LIMIT 50;

-- ---------- runs ----------

-- name: RequestVulnRun :exec
INSERT INTO vulnmon_runs (id) SELECT $1
WHERE NOT EXISTS (SELECT 1 FROM vulnmon_runs WHERE status IN ('queued', 'running'));

-- name: ClaimVulnRun :one
UPDATE vulnmon_runs SET status = 'running', started_at = now()
WHERE id = (SELECT id FROM vulnmon_runs WHERE status = 'queued' ORDER BY requested_at LIMIT 1 FOR UPDATE SKIP LOCKED)
RETURNING *;

-- name: FinishVulnRun :exec
UPDATE vulnmon_runs SET status = $2, finished_at = now(), advisories = $3, matches = $4, new_matches = $5, log = $6
WHERE id = $1;

-- name: LastVulnRun :one
SELECT * FROM vulnmon_runs ORDER BY requested_at DESC LIMIT 1;

-- name: LastCompletedVulnRun :one
SELECT * FROM vulnmon_runs WHERE status = 'completed' ORDER BY finished_at DESC LIMIT 1;

-- name: FailStaleVulnRuns :exec
UPDATE vulnmon_runs SET status = 'failed', finished_at = now(), log = log || E'\nworker stopped'
WHERE status = 'running' AND started_at < now() - interval '2 hours';
