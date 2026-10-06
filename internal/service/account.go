package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// TOTPEnrollment is shown while setting up 2FA.
type TOTPEnrollment struct {
	Secret string // base32, for manual entry
	URI    string // otpauth:// for the QR code
}

// BeginTOTP generates and stores (encrypted, not yet enabled) a new secret.
func (s *Service) BeginTOTP(ctx context.Context, p *auth.Principal) (*TOTPEnrollment, error) {
	if p.ViaToken() {
		return nil, ErrForbidden
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return nil, err
	}
	ct, nonce, err := s.box.Seal(secret, totpAAD(p.UserID))
	if err != nil {
		return nil, err
	}
	err = s.db.Tx(ctx, store.Scope{UserID: p.UserID}, func(q *db.Queries) error {
		u, err := q.GetUserByID(ctx, p.UserID)
		if err != nil {
			return err
		}
		if u.TotpEnabled {
			return ErrConflict
		}
		return q.SetUserTOTPSecret(ctx, db.SetUserTOTPSecretParams{ID: p.UserID, TotpSecretEnc: ct, TotpNonce: nonce})
	})
	if err != nil {
		return nil, wrap("begin totp", err)
	}
	return &TOTPEnrollment{Secret: auth.EncodeTOTPSecret(secret), URI: auth.TOTPURI(s.cfg.Issuer, p.Email, secret)}, nil
}

// PendingTOTP returns the enrollment data for a secret created by BeginTOTP
// that has not been confirmed yet (so the QR survives a page reload).
func (s *Service) PendingTOTP(ctx context.Context, p *auth.Principal) (*TOTPEnrollment, error) {
	var out *TOTPEnrollment
	err := s.db.Tx(ctx, store.Scope{UserID: p.UserID}, func(q *db.Queries) error {
		u, err := q.GetUserByID(ctx, p.UserID)
		if err != nil {
			return err
		}
		if u.TotpEnabled || u.TotpSecretEnc == nil {
			return ErrNotFound
		}
		secret, err := s.box.Open(u.TotpSecretEnc, u.TotpNonce, totpAAD(u.ID))
		if err != nil {
			return err
		}
		out = &TOTPEnrollment{Secret: auth.EncodeTOTPSecret(secret), URI: auth.TOTPURI(s.cfg.Issuer, u.Email, secret)}
		return nil
	})
	return out, wrap("pending totp", err)
}

// ConfirmTOTP enables 2FA after the user proves possession with a code.
func (s *Service) ConfirmTOTP(ctx context.Context, p *auth.Principal, code string, m Meta) error {
	return wrap("confirm totp", s.db.Tx(ctx, store.Scope{UserID: p.UserID}, func(q *db.Queries) error {
		u, err := q.GetUserByID(ctx, p.UserID)
		if err != nil {
			return err
		}
		if u.TotpSecretEnc == nil || u.TotpEnabled {
			return ErrConflict
		}
		secret, err := s.box.Open(u.TotpSecretEnc, u.TotpNonce, totpAAD(u.ID))
		if err != nil {
			return err
		}
		step, ok := auth.VerifyTOTP(secret, code, s.now())
		if !ok || !s.replay.Use(u.ID.String(), step, s.now()) {
			return invalid("code", "invalid")
		}
		if err := q.EnableUserTOTP(ctx, u.ID); err != nil {
			return err
		}
		return audit(ctx, q, nil, &u.ID, "user.totp_enabled", "user", u.ID.String(), m, nil)
	}))
}

// DisableTOTP turns 2FA off after re-checking the password. Superadmins
// cannot disable it while it is required.
func (s *Service) DisableTOTP(ctx context.Context, p *auth.Principal, password string, m Meta) error {
	if p.IsSuperadmin && s.cfg.RequireAdmin2FA {
		return ErrForbidden
	}
	return wrap("disable totp", s.db.Tx(ctx, store.Scope{UserID: p.UserID}, func(q *db.Queries) error {
		u, err := q.GetUserByID(ctx, p.UserID)
		if err != nil {
			return err
		}
		if ok, _, err := auth.VerifyPassword(password, u.PasswordHash); err != nil || !ok {
			return invalid("password", "invalid")
		}
		if err := q.DisableUserTOTP(ctx, u.ID); err != nil {
			return err
		}
		return audit(ctx, q, nil, &u.ID, "user.totp_disabled", "user", u.ID.String(), m, nil)
	}))
}

// ChangePassword verifies the current password, stores the new one and logs
// out every other session.
func (s *Service) ChangePassword(ctx context.Context, sess *Session, current, next string, m Meta) error {
	p := sess.Principal
	if err := auth.ValidatePassword(next, p.Email); err != nil {
		return invalid("new_password", err.Error())
	}
	hash, err := auth.HashPassword(next)
	if err != nil {
		return err
	}
	return wrap("change password", s.db.Tx(ctx, store.Scope{UserID: p.UserID}, func(q *db.Queries) error {
		u, err := q.GetUserByID(ctx, p.UserID)
		if err != nil {
			return err
		}
		if ok, _, err := auth.VerifyPassword(current, u.PasswordHash); err != nil || !ok {
			return invalid("current_password", "invalid")
		}
		if err := q.UpdateUserPassword(ctx, db.UpdateUserPasswordParams{ID: u.ID, PasswordHash: hash}); err != nil {
			return err
		}
		if err := q.DeleteUserSessionsExcept(ctx, db.DeleteUserSessionsExceptParams{UserID: u.ID, KeepID: sess.ID}); err != nil {
			return err
		}
		return audit(ctx, q, nil, &u.ID, "user.password_changed", "user", u.ID.String(), m, nil)
	}))
}

// UpdateProfile changes name and language.
func (s *Service) UpdateProfile(ctx context.Context, p *auth.Principal, name, locale string) error {
	name, err := cleanName("name", name, 1, 200)
	if err != nil {
		return err
	}
	if locale != "" && locale != "tr" && locale != "en" {
		return invalid("locale", "invalid")
	}
	return wrap("update profile", s.db.Tx(ctx, store.Scope{UserID: p.UserID}, func(q *db.Queries) error {
		return q.UpdateUserProfile(ctx, db.UpdateUserProfileParams{ID: p.UserID, Name: name, Locale: locale})
	}))
}

// SessionInfo describes an active session for the account page.
type SessionInfo struct {
	ID         uuid.UUID
	IP         string
	UserAgent  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	Current    bool
}

// ListSessions returns the user's active sessions.
func (s *Service) ListSessions(ctx context.Context, sess *Session) ([]SessionInfo, error) {
	var out []SessionInfo
	err := s.db.Tx(ctx, store.Scope{UserID: sess.Principal.UserID}, func(q *db.Queries) error {
		rows, err := q.ListUserSessions(ctx, sess.Principal.UserID)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.MfaPending {
				continue
			}
			out = append(out, SessionInfo{ID: r.ID, IP: r.Ip, UserAgent: r.UserAgent, CreatedAt: r.CreatedAt, LastSeenAt: r.LastSeenAt, Current: r.ID == sess.ID})
		}
		return nil
	})
	return out, wrap("list sessions", err)
}

// RevokeSession ends one of the user's own sessions.
func (s *Service) RevokeSession(ctx context.Context, sess *Session, id uuid.UUID, m Meta) error {
	return wrap("revoke session", s.db.Tx(ctx, store.Scope{UserID: sess.Principal.UserID}, func(q *db.Queries) error {
		n, err := q.DeleteUserSession(ctx, db.DeleteUserSessionParams{UserID: sess.Principal.UserID, SessionID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		uid := sess.Principal.UserID
		return audit(ctx, q, nil, &uid, "session.revoked", "session", id.String(), m, nil)
	}))
}
