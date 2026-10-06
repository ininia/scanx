package auth

import (
	"context"

	"github.com/google/uuid"
)

// Role is an organization membership role.
type Role string

// Roles, most privileged first.
const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

var roleRank = map[Role]int{RoleViewer: 1, RoleMember: 2, RoleAdmin: 3, RoleOwner: 4}

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { _, ok := roleRank[Role(r)]; return ok }

// AtLeast reports whether r grants at least the privileges of min.
func (r Role) AtLeast(min Role) bool { return roleRank[r] >= roleRank[min] && roleRank[r] > 0 }

// Action is a permission checked by handlers.
type Action string

// Actions (spec §9 authorization column).
const (
	ActOrgRead        Action = "org.read"
	ActOrgUpdate      Action = "org.update"
	ActMembersManage  Action = "members.manage"
	ActProjectRead    Action = "project.read"
	ActProjectWrite   Action = "project.write"
	ActProjectDelete  Action = "project.delete"
	ActAuditRead      Action = "audit.read"
	ActTokenOwn       Action = "token.own" // manage one's own API tokens
	ActScanTrigger    Action = "scan.trigger"
	ActIssueUpdate    Action = "issue.update"
	ActOwnershipGrant Action = "ownership.grant"
)

var minRole = map[Action]Role{
	ActOrgRead:        RoleViewer,
	ActProjectRead:    RoleViewer,
	ActTokenOwn:       RoleViewer,
	ActProjectWrite:   RoleMember,
	ActScanTrigger:    RoleMember,
	ActIssueUpdate:    RoleMember,
	ActOrgUpdate:      RoleAdmin,
	ActMembersManage:  RoleAdmin,
	ActProjectDelete:  RoleAdmin,
	ActAuditRead:      RoleAdmin,
	ActOwnershipGrant: RoleOwner,
}

// Can reports whether role may perform act. Unknown actions are denied.
func Can(role Role, act Action) bool {
	min, ok := minRole[act]
	return ok && role.AtLeast(min)
}

// Principal is the authenticated caller.
type Principal struct {
	UserID       uuid.UUID
	Email        string
	Name         string
	Locale       string
	IsSuperadmin bool
	SessionID    uuid.UUID // zero for API tokens
	// Token-authenticated callers are restricted to one org and to scopes.
	TokenID     uuid.UUID
	TokenOrgID  uuid.UUID
	TokenScopes []string
}

// ViaToken reports whether the caller used an API token.
func (p *Principal) ViaToken() bool { return p.TokenID != uuid.Nil }

// HasScope reports whether a token-authenticated caller has scope s.
// Session-authenticated callers have every scope (roles still apply).
func (p *Principal) HasScope(s string) bool {
	if !p.ViaToken() {
		return true
	}
	for _, x := range p.TokenScopes {
		if x == s || (s == "read" && x == "write") {
			return true
		}
	}
	return false
}

type principalKey struct{}

// WithPrincipal stores p in ctx.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal or nil.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}
