-- name: CreateOrg :one
INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3) RETURNING *;

-- name: GetOrgBySlug :one
SELECT * FROM organizations WHERE slug = $1;

-- name: GetOrgByID :one
SELECT * FROM organizations WHERE id = $1;

-- name: UpdateOrg :one
UPDATE organizations SET name = $2 WHERE id = $1 RETURNING *;

-- name: ListOrgsForUser :many
-- RLS limits rows to orgs the current user belongs to (or all for superadmin
-- when the superadmin flag is set on the transaction).
SELECT o.*, m.role
FROM organizations o JOIN memberships m ON m.org_id = o.id
WHERE m.user_id = $1
ORDER BY o.name;

-- name: ListAllOrgs :many
SELECT o.*, (SELECT count(*) FROM memberships m WHERE m.org_id = o.id) AS member_count
FROM organizations o ORDER BY o.name LIMIT $1 OFFSET $2;

-- name: AddMember :exec
INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, $3);

-- name: GetMembership :one
SELECT * FROM memberships WHERE org_id = $1 AND user_id = $2;

-- name: ListMembers :many
SELECT m.org_id, m.user_id, m.role, m.created_at, u.email, u.name, u.totp_enabled, u.last_login_at
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = $1 ORDER BY u.email;

-- name: UpdateMemberRole :execrows
UPDATE memberships SET role = $3 WHERE org_id = $1 AND user_id = $2;

-- name: RemoveMember :execrows
DELETE FROM memberships WHERE org_id = $1 AND user_id = $2;

-- name: CountOwners :one
SELECT count(*) FROM memberships WHERE org_id = $1 AND role = 'owner';

-- name: CreateInvitation :exec
INSERT INTO invitations (id, org_id, email, role, token_hash, invited_by, expires_at)
VALUES ($1, $2, lower(sqlc.arg(email)), $3, $4, $5, $6);

-- name: ListInvitations :many
SELECT id, org_id, email, role, invited_by, expires_at, accepted_at, created_at
FROM invitations WHERE org_id = $1 AND accepted_at IS NULL ORDER BY created_at DESC;

-- name: DeleteInvitation :execrows
DELETE FROM invitations WHERE org_id = $1 AND id = $2;

-- name: LookupInvitation :one
SELECT l.id::uuid AS id, l.org_id::uuid AS org_id, l.email::text AS email, l.role::text AS role,
       l.expires_at::timestamptz AS expires_at,
       coalesce(l.accepted_at, '0001-01-01 00:00:00+00'::timestamptz)::timestamptz AS accepted_at, l.org_name::text AS org_name
FROM scanx_lookup_invitation(sqlc.arg(token_hash)::bytea) AS l;

-- name: AcceptInvitation :execrows
UPDATE invitations SET accepted_at = now() WHERE id = $1 AND accepted_at IS NULL AND expires_at > now();
