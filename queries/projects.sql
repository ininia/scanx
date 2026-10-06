-- name: CreateProject :one
INSERT INTO projects (id, org_id, name, slug, repo_url, provider, auth_mode, branches, schedule_cron)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: ListProjects :many
SELECT * FROM projects
WHERE org_id = $1 AND (sqlc.arg(include_archived)::bool OR archived_at IS NULL)
ORDER BY name LIMIT $2 OFFSET $3;

-- name: CountProjects :one
SELECT count(*) FROM projects
WHERE org_id = $1 AND (sqlc.arg(include_archived)::bool OR archived_at IS NULL);

-- name: GetProjectBySlug :one
SELECT * FROM projects WHERE org_id = $1 AND slug = $2;

-- name: GetProjectByID :one
SELECT * FROM projects WHERE id = $1;

-- name: UpdateProject :one
UPDATE projects
SET name = $3, repo_url = $4, provider = $5, branches = $6, schedule_cron = $7, updated_at = now()
WHERE org_id = $1 AND id = $2
RETURNING *;

-- name: ArchiveProject :execrows
UPDATE projects SET archived_at = now(), updated_at = now() WHERE org_id = $1 AND id = $2 AND archived_at IS NULL;

-- name: DeleteProject :execrows
DELETE FROM projects WHERE org_id = $1 AND id = $2;
