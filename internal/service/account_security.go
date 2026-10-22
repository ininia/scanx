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

// PasswordResetTTL is how long an admin-created reset link stays valid.
const PasswordResetTTL = 24 * time.Hour

// checkManageMember lets an org admin act on another member's account:
// owners only by owners, superadmins only by superadmins, and users that
// also belong to other organizations only by superadmins (an org admin
// must not take over an account another org relies on).
func (s *Service) checkManageMember(ctx context.Context, q *db.Queries, o *OrgCtx, user uuid.UUID) (db.User, error) {
	cur, err := q.GetMembership(ctx, db.GetMembershipParams{OrgID: o.Org.ID, UserID: user})
	if err != nil {
		return db.User{}, store.NotFound(err)
	}
	if auth.Role(cur.Role) == auth.RoleOwner && !auth.Can(o.Role, auth.ActOwnershipGrant) {
		return db.User{}, ErrForbidden
	}
	u, err := q.GetUserByID(ctx, user)
	if err != nil {
		return db.User{}, store.NotFound(err)
	}
	if o.P.IsSuperadmin {
		return u, nil
	}
	if u.IsSuperadmin {
		return db.User{}, ErrForbidden
	}
	n, err := q.CountUserMemberships(ctx, user)
	if err != nil {
		return db.User{}, err
	}
	if n > 1 {
		return db.User{}, ErrForbidden
	}
	return u, nil
}

// SetMemberRequireTOTP makes 2FA mandatory (or optional again) for a
// member; a member without 2FA must enroll at the next request.
func (s *Service) SetMemberRequireTOTP(ctx context.Context, o *OrgCtx, user uuid.UUID, require bool, m Meta) error {
	if err := o.Require(auth.ActMembersManage, "write"); err != nil {
		return err
	}
	return wrap("require 2fa", s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		cur, err := q.GetMembership(ctx, db.GetMembershipParams{OrgID: o.Org.ID, UserID: user})
		if err != nil {
			return store.NotFound(err)
		}
		// Turning the requirement on only adds protection; turning it off
		// needs the same rights as managing the account.
		if !require {
			if _, err := s.checkManageMember(ctx, q, o, user); err != nil {
				return err
			}
		} else if auth.Role(cur.Role) == auth.RoleOwner && !auth.Can(o.Role, auth.ActOwnershipGrant) {
			return ErrForbidden
		}
		if err := q.SetUserRequireTOTP(ctx, db.SetUserRequireTOTPParams{ID: user, RequireTotp: require}); err != nil {
			return err
		}
		action := "member.2fa_required"
		if !require {
			action = "member.2fa_optional"
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, action, "user", user.String(), m, nil)
	}))
}

// PasswordReset is a newly created reset link; Token is shown once.
type PasswordReset struct {
	Email     string
	Token     string
	ExpiresAt time.Time
}

// CreatePasswordReset creates a one-time password reset link for a member.
// Older open links for the user are invalidated.
func (s *Service) CreatePasswordReset(ctx context.Context, o *OrgCtx, user uuid.UUID, m Meta) (*PasswordReset, error) {
	if err := o.Require(auth.ActMembersManage, "write"); err != nil {
		return nil, err
	}
	if o.P.ViaToken() || user == o.P.UserID {
		return nil, ErrForbidden
	}
	plain, hash, err := auth.NewToken(auth.PrefixReset)
	if err != nil {
		return nil, err
	}
	out := &PasswordReset{Token: plain, ExpiresAt: s.now().Add(PasswordResetTTL)}
	err = s.db.Tx(ctx, o.Scope(), func(q *db.Queries) error {
		u, err := s.checkManageMember(ctx, q, o, user)
		if err != nil {
			return err
		}
		out.Email = u.Email
		if err := q.InvalidatePasswordResets(ctx, user); err != nil {
			return err
		}
		if err := q.CreatePasswordReset(ctx, db.CreatePasswordResetParams{
			ID: newID(), UserID: user, OrgID: &o.Org.ID, TokenHash: hash, CreatedBy: &o.P.UserID, ExpiresAt: out.ExpiresAt,
		}); err != nil {
			return err
		}
		return audit(ctx, q, &o.Org.ID, &o.P.UserID, "member.password_reset_link", "user", user.String(), m, nil)
	})
	if err != nil {
		return nil, wrap("password reset", err)
	}
	return out, nil
}

// PasswordResetInfo is shown on the reset page.
type PasswordResetInfo struct {
	ID     uuid.UUID
	UserID uuid.UUID
	OrgID  *uuid.UUID
	Email  string
	Name   string
}

// LookupPasswordReset validates a reset token.
func (s *Service) LookupPasswordReset(ctx context.Context, token string) (*PasswordResetInfo, error) {
	if !strings.HasPrefix(token, auth.PrefixReset) {
		return nil, ErrNotFound
	}
	var out *PasswordResetInfo
	err := s.db.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		r, err := q.LookupPasswordReset(ctx, auth.HashToken(token))
		if err != nil {
			return store.NotFound(err)
		}
		out = &PasswordResetInfo{ID: r.ID, UserID: r.UserID, OrgID: r.OrgID, Email: r.Email, Name: r.Name}
		return nil
	})
	return out, wrap("lookup password reset", err)
}

// ResetPassword sets a new password from a reset link. All sessions of the
// user are ended; 2FA (if enabled) is still asked at the next login.
func (s *Service) ResetPassword(ctx context.Context, token, password string, m Meta) error {
	info, err := s.LookupPasswordReset(ctx, token)
	if err != nil {
		return err
	}
	if err := auth.ValidatePassword(password, info.Email); err != nil {
		return invalid("password", err.Error())
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	scope := store.Scope{UserID: info.UserID}
	if info.OrgID != nil {
		scope.OrgID = *info.OrgID
	}
	return wrap("reset password", s.db.Tx(ctx, scope, func(q *db.Queries) error {
		n, err := q.UsePasswordReset(ctx, info.ID)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		if err := q.ResetUserPassword(ctx, db.ResetUserPasswordParams{ID: info.UserID, PasswordHash: hash}); err != nil {
			return err
		}
		if err := q.DeleteUserSessions(ctx, info.UserID); err != nil {
			return err
		}
		return audit(ctx, q, info.OrgID, &info.UserID, "user.password_reset", "user", info.UserID.String(), m, nil)
	}))
}
