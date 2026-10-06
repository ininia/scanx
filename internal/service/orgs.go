package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// OrgCtx is a resolved organization plus the caller's role in it.
type OrgCtx struct {
	Org  db.Organization
	Role auth.Role
	P    *auth.Principal
}

// Scope returns the tenant scope for queries inside this org.
func (o *OrgCtx) Scope() store.Scope {
	return store.Scope{OrgID: o.Org.ID, UserID: o.P.UserID, Superadmin: o.P.IsSuperadmin}
}

// Require fails with ErrForbidden unless the caller may perform act. API
// tokens additionally need the matching scope.
func (o *OrgCtx) Require(act auth.Action, scope string) error {
	if !auth.Can(o.Role, act) || !o.P.HasScope(scope) {
		return ErrForbidden
	}
	return nil
}

// ResolveOrg finds an org by slug that the caller may see. Organizations the
// caller does not belong to are reported as ErrNotFound (never 403), so their
// existence is not revealed (spec §5.4).
func (s *Service) ResolveOrg(ctx context.Context, p *auth.Principal, slug string) (*OrgCtx, error) {
	if p == nil {
		return nil, ErrUnauthorized
	}
	if validSlug(slug) != nil {
		return nil, ErrNotFound
	}
	var out *OrgCtx
	err := s.db.Tx(ctx, store.Scope{UserID: p.UserID, Superadmin: p.IsSuperadmin}, func(q *db.Queries) error {
		org, err := q.GetOrgBySlug(ctx, slug)
		if err != nil {
			return store.NotFound(err)
		}
		if p.ViaToken() && org.ID != p.TokenOrgID {
			return ErrNotFound
		}
		role := auth.RoleOwner // superadmins act as owners
		m, err := q.GetMembership(ctx, db.GetMembershipParams{OrgID: org.ID, UserID: p.UserID})
		switch {
		case err == nil:
			role = auth.Role(m.Role)
		case !p.IsSuperadmin:
			return ErrNotFound
		}
		out = &OrgCtx{Org: org, Role: role, P: p}
		return nil
	})
	return out, wrap("resolve org", err)
}

// MyOrg is an org in the caller's org switcher.
type MyOrg struct {
	ID   uuid.UUID
	Name string
	Slug string
	Role auth.Role
}

// ListMyOrgs lists organizations the caller is a member of.
func (s *Service) ListMyOrgs(ctx context.Context, p *auth.Principal) ([]MyOrg, error) {
	var out []MyOrg
	err := s.db.Tx(ctx, store.Scope{UserID: p.UserID}, func(q *db.Queries) error {
		rows, err := q.ListOrgsForUser(ctx, p.UserID)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if p.ViaToken() && r.ID != p.TokenOrgID {
				continue
			}
			out = append(out, MyOrg{ID: r.ID, Name: r.Name, Slug: r.Slug, Role: auth.Role(r.Role)})
		}
		return nil
	})
	return out, wrap("list orgs", err)
}

// CreateOrg creates an organization owned by the caller. Only superadmins
// may do this unless AllowOrgCreation is set (SaaS signup mode).
func (s *Service) CreateOrg(ctx context.Context, p *auth.Principal, name, slug string, m Meta) (*db.Organization, error) {
	if p.ViaToken() || (!p.IsSuperadmin && !s.cfg.AllowOrgCreation) {
		return nil, ErrForbidden
	}
	name, err := cleanName("name", name, 1, 200)
	if err != nil {
		return nil, err
	}
	if slug == "" {
		slug = Slugify(name)
	}
	if err := validSlug(slug); err != nil {
		return nil, err
	}
	id := newID()
	var org db.Organization
	err = s.db.Tx(ctx, store.Scope{OrgID: id, UserID: p.UserID}, func(q *db.Queries) error {
		var err error
		org, err = q.CreateOrg(ctx, db.CreateOrgParams{ID: id, Name: name, Slug: slug})
		if err != nil {
			if isUniqueViolation(err) {
				return invalid("slug", "taken")
			}
			return err
		}
		if err := q.AddMember(ctx, db.AddMemberParams{OrgID: id, UserID: p.UserID, Role: string(auth.RoleOwner)}); err != nil {
			return err
		}
		return audit(ctx, q, &id, &p.UserID, "org.created", "org", id.String(), m, map[string]any{"slug": slug})
	})
	if err != nil {
		return nil, wrap("create org", err)
	}
	return &org, nil
}

// UpdateOrg renames an organization.
func (s *Service) UpdateOrg(ctx context.Context, o *OrgCtx, name string, m Meta) (*db.Organization, error) {
	if err := o.Require(auth.ActOrgUpdate, "write"); err != nil {
		return nil, err
	}
	name, err := cleanName("name", name, 1, 200)
	if err != nil {
		return nil, err
	}
	var org db.Organization
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		if org, err = q.UpdateOrg(ctx, db.UpdateOrgParams{ID: o.Org.ID, Name: name}); err != nil {
			return store.NotFound(err)
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "org.updated", "org", o.Org.ID.String(), m, nil)
	})
	return &org, wrap("update org", err)
}

// ListAllOrgs is the superadmin overview.
func (s *Service) ListAllOrgs(ctx context.Context, p *auth.Principal) ([]db.ListAllOrgsRow, error) {
	if !p.IsSuperadmin || p.ViaToken() {
		return nil, ErrForbidden
	}
	var out []db.ListAllOrgsRow
	err := s.db.Tx(ctx, store.Scope{UserID: p.UserID, Superadmin: true}, func(q *db.Queries) error {
		var err error
		out, err = q.ListAllOrgs(ctx, db.ListAllOrgsParams{Limit: 500, Offset: 0})
		return err
	})
	return out, wrap("list all orgs", err)
}

// --- members ---

// ListMembers lists members of the org.
func (s *Service) ListMembers(ctx context.Context, o *OrgCtx) ([]db.ListMembersRow, error) {
	if err := o.Require(auth.ActOrgRead, "read"); err != nil {
		return nil, err
	}
	var out []db.ListMembersRow
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		out, err = q.ListMembers(ctx, o.Org.ID)
		return err
	})
	return out, wrap("list members", err)
}

// AddExistingMember adds an already registered user by e-mail.
func (s *Service) AddExistingMember(ctx context.Context, o *OrgCtx, email, role string, m Meta) error {
	if err := s.checkRoleGrant(o, role); err != nil {
		return err
	}
	email, err := cleanEmail(email)
	if err != nil {
		return err
	}
	return wrap("add member", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		u, err := q.GetUserByEmail(ctx, email)
		if err != nil {
			return store.NotFound(err)
		}
		if err := q.AddMember(ctx, db.AddMemberParams{OrgID: o.Org.ID, UserID: u.ID, Role: role}); err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "member.added", "user", u.ID.String(), m, map[string]any{"role": role})
	}))
}

func (s *Service) checkRoleGrant(o *OrgCtx, role string) error {
	if err := o.Require(auth.ActMembersManage, "write"); err != nil {
		return err
	}
	if !auth.ValidRole(role) {
		return invalid("role", "invalid")
	}
	if auth.Role(role) == auth.RoleOwner && !auth.Can(o.Role, auth.ActOwnershipGrant) {
		return ErrForbidden
	}
	return nil
}

// UpdateMemberRole changes a member's role, keeping at least one owner.
func (s *Service) UpdateMemberRole(ctx context.Context, o *OrgCtx, user uuid.UUID, role string, m Meta) error {
	if err := s.checkRoleGrant(o, role); err != nil {
		return err
	}
	return wrap("update member", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		cur, err := q.GetMembership(ctx, db.GetMembershipParams{OrgID: o.Org.ID, UserID: user})
		if err != nil {
			return store.NotFound(err)
		}
		if auth.Role(cur.Role) == auth.RoleOwner && !auth.Can(o.Role, auth.ActOwnershipGrant) {
			return ErrForbidden
		}
		if cur.Role == string(auth.RoleOwner) && role != string(auth.RoleOwner) {
			n, err := q.CountOwners(ctx, o.Org.ID)
			if err != nil {
				return err
			}
			if n <= 1 {
				return ErrLastOwner
			}
		}
		if _, err := q.UpdateMemberRole(ctx, db.UpdateMemberRoleParams{OrgID: o.Org.ID, UserID: user, Role: role}); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "member.role_changed", "user", user.String(), m,
			map[string]any{"from": cur.Role, "to": role})
	}))
}

// RemoveMember removes a member (or lets a member leave), keeping an owner.
func (s *Service) RemoveMember(ctx context.Context, o *OrgCtx, user uuid.UUID, m Meta) error {
	self := user == o.P.UserID
	if !self {
		if err := o.Require(auth.ActMembersManage, "write"); err != nil {
			return err
		}
	}
	return wrap("remove member", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		cur, err := q.GetMembership(ctx, db.GetMembershipParams{OrgID: o.Org.ID, UserID: user})
		if err != nil {
			return store.NotFound(err)
		}
		if cur.Role == string(auth.RoleOwner) {
			if !self && !auth.Can(o.Role, auth.ActOwnershipGrant) {
				return ErrForbidden
			}
			n, err := q.CountOwners(ctx, o.Org.ID)
			if err != nil {
				return err
			}
			if n <= 1 {
				return ErrLastOwner
			}
		}
		if _, err := q.RemoveMember(ctx, db.RemoveMemberParams{OrgID: o.Org.ID, UserID: user}); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "member.removed", "user", user.String(), m, nil)
	}))
}

// --- invitations (no SMTP needed: the link is shown to the admin) ---

// Invitation is a newly created invitation; Link holds the one-time token.
type Invitation struct {
	ID        uuid.UUID
	Email     string
	Role      string
	Token     string
	ExpiresAt time.Time
}

// Invite creates an invitation for e-mail with role.
func (s *Service) Invite(ctx context.Context, o *OrgCtx, email, role string, m Meta) (*Invitation, error) {
	if err := s.checkRoleGrant(o, role); err != nil {
		return nil, err
	}
	email, err := cleanEmail(email)
	if err != nil {
		return nil, err
	}
	plain, hash, err := auth.NewToken(auth.PrefixInvite)
	if err != nil {
		return nil, err
	}
	inv := &Invitation{ID: newID(), Email: email, Role: role, Token: plain, ExpiresAt: s.now().Add(s.cfg.InvitationTTL)}
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		if err := q.CreateInvitation(ctx, db.CreateInvitationParams{
			ID: inv.ID, OrgID: o.Org.ID, Email: email, Role: role, TokenHash: hash, InvitedBy: &o.P.UserID, ExpiresAt: inv.ExpiresAt,
		}); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "member.invited", "invitation", inv.ID.String(), m,
			map[string]any{"email": email, "role": role})
	})
	if err != nil {
		return nil, wrap("invite", err)
	}
	return inv, nil
}

// ListInvitations lists open invitations.
func (s *Service) ListInvitations(ctx context.Context, o *OrgCtx) ([]db.ListInvitationsRow, error) {
	if err := o.Require(auth.ActMembersManage, "read"); err != nil {
		return nil, err
	}
	var out []db.ListInvitationsRow
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		out, err = q.ListInvitations(ctx, o.Org.ID)
		return err
	})
	return out, wrap("list invitations", err)
}

// RevokeInvitation deletes an open invitation.
func (s *Service) RevokeInvitation(ctx context.Context, o *OrgCtx, id uuid.UUID, m Meta) error {
	if err := o.Require(auth.ActMembersManage, "write"); err != nil {
		return err
	}
	return wrap("revoke invitation", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		n, err := q.DeleteInvitation(ctx, db.DeleteInvitationParams{OrgID: o.Org.ID, ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "invitation.revoked", "invitation", id.String(), m, nil)
	}))
}

// InvitationInfo is shown on the acceptance page.
type InvitationInfo struct {
	ID         uuid.UUID
	OrgID      uuid.UUID
	OrgName    string
	Email      string
	Role       string
	UserExists bool
}

// LookupInvitation validates an invitation token.
func (s *Service) LookupInvitation(ctx context.Context, token string) (*InvitationInfo, error) {
	if !strings.HasPrefix(token, auth.PrefixInvite) {
		return nil, ErrNotFound
	}
	var out *InvitationInfo
	err := s.db.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		inv, err := q.LookupInvitation(ctx, auth.HashToken(token))
		if err != nil {
			return store.NotFound(err)
		}
		if !inv.AcceptedAt.IsZero() || inv.ExpiresAt.Before(s.now()) {
			return ErrNotFound
		}
		out = &InvitationInfo{ID: inv.ID, OrgID: inv.OrgID, OrgName: inv.OrgName, Email: inv.Email, Role: inv.Role}
		if _, err := q.GetUserByEmail(ctx, inv.Email); err == nil {
			out.UserExists = true
		}
		return nil
	})
	return out, wrap("lookup invitation", err)
}

// AcceptInvitation joins the org. A logged-in user must own the invited
// e-mail; otherwise a new account is created with name and password.
func (s *Service) AcceptInvitation(ctx context.Context, token string, current *auth.Principal, name, password string, m Meta) (*LoginResult, error) {
	info, err := s.LookupInvitation(ctx, token)
	if err != nil {
		return nil, err
	}
	var userID uuid.UUID
	var res *LoginResult
	switch {
	case current != nil:
		if !strings.EqualFold(current.Email, info.Email) {
			return nil, ErrForbidden
		}
		userID = current.UserID
	case info.UserExists:
		return nil, ErrUnauthorized // must log in first
	default:
		if name, err = cleanName("name", name, 1, 200); err != nil {
			return nil, err
		}
		if err := auth.ValidatePassword(password, info.Email); err != nil {
			return nil, invalid("password", err.Error())
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			return nil, err
		}
		err = s.db.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
			u, err := q.CreateUser(ctx, db.CreateUserParams{ID: newID(), Email: info.Email, Name: name, PasswordHash: hash})
			if err != nil {
				if isUniqueViolation(err) {
					return ErrConflict
				}
				return err
			}
			userID = u.ID
			res, err = s.createSession(ctx, q, u.ID, false, &info.OrgID, m)
			return err
		})
		if err != nil {
			return nil, wrap("accept invitation", err)
		}
	}
	err = s.db.Tx(ctx, store.Scope{OrgID: info.OrgID, UserID: userID}, func(q *db.Queries) error {
		n, err := q.AcceptInvitation(ctx, info.ID)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		if err := q.AddMember(ctx, db.AddMemberParams{OrgID: info.OrgID, UserID: userID, Role: info.Role}); err != nil {
			if isUniqueViolation(err) {
				return nil // already a member: accepting again is harmless
			}
			return err
		}
		return audit(ctx, q, &info.OrgID, &userID, "member.joined", "user", userID.String(), m, map[string]any{"role": info.Role})
	})
	return res, wrap("accept invitation", err)
}

// --- API tokens ---

// NewAPIToken is returned once at creation.
type NewAPIToken struct {
	ID    uuid.UUID
	Token string
}

// CreateAPIToken creates a personal token in the org (spec §5.3).
func (s *Service) CreateAPIToken(ctx context.Context, o *OrgCtx, name string, scopes []string, ttlDays int, m Meta) (*NewAPIToken, error) {
	if o.P.ViaToken() {
		return nil, ErrForbidden // tokens cannot mint tokens
	}
	if err := o.Require(auth.ActTokenOwn, "write"); err != nil {
		return nil, err
	}
	name, err := cleanName("name", name, 1, 100)
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		scopes = []string{"read"}
	}
	for _, sc := range scopes {
		if sc != "read" && sc != "write" {
			return nil, invalid("scopes", "invalid")
		}
	}
	if ttlDays < 0 || ttlDays > 3650 {
		return nil, invalid("expires_in_days", "invalid")
	}
	var exp *time.Time
	if ttlDays > 0 {
		exp = ptr(s.now().Add(time.Duration(ttlDays) * 24 * time.Hour))
	}
	plain, hash, err := auth.NewToken(auth.PrefixPersonal)
	if err != nil {
		return nil, err
	}
	out := &NewAPIToken{ID: newID(), Token: plain}
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		if err := q.CreateAPIToken(ctx, db.CreateAPITokenParams{
			ID: out.ID, OrgID: o.Org.ID, UserID: &o.P.UserID, Name: name, TokenPrefix: auth.TokenDisplayPrefix(plain),
			TokenHash: hash, Scopes: scopes, ExpiresAt: exp,
		}); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "token.created", "token", out.ID.String(), m,
			map[string]any{"name": name, "scopes": scopes})
	})
	if err != nil {
		return nil, wrap("create token", err)
	}
	return out, nil
}

// ListAPITokens lists the caller's tokens in the org.
func (s *Service) ListAPITokens(ctx context.Context, o *OrgCtx) ([]db.ListUserAPITokensRow, error) {
	var out []db.ListUserAPITokensRow
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		out, err = q.ListUserAPITokens(ctx, db.ListUserAPITokensParams{OrgID: o.Org.ID, UserID: &o.P.UserID})
		return err
	})
	return out, wrap("list tokens", err)
}

// RevokeAPIToken revokes one of the caller's tokens.
func (s *Service) RevokeAPIToken(ctx context.Context, o *OrgCtx, id uuid.UUID, m Meta) error {
	return wrap("revoke token", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		n, err := q.RevokeUserAPIToken(ctx, db.RevokeUserAPITokenParams{OrgID: o.Org.ID, UserID: &o.P.UserID, ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "token.revoked", "token", id.String(), m, nil)
	}))
}

// --- audit log ---

// ListAudit returns recent audit entries of the org.
func (s *Service) ListAudit(ctx context.Context, o *OrgCtx, limit, offset int) ([]db.ListAuditLogsRow, error) {
	if err := o.Require(auth.ActAuditRead, "read"); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []db.ListAuditLogsRow
	err := s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		var err error
		out, err = q.ListAuditLogs(ctx, db.ListAuditLogsParams{OrgID: &o.Org.ID, Limit: int32(limit), Offset: int32(max(offset, 0))}) //nolint:gosec // bounded
		return err
	})
	return out, wrap("list audit", err)
}
