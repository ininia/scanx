package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// LoginResult is returned by Login and VerifyMFA.
type LoginResult struct {
	SessionToken string // cookie value (shown once, never stored)
	MFAPending   bool
	UserID       uuid.UUID
	ExpiresAt    time.Time
}

// Session is an authenticated browser session.
type Session struct {
	ID          uuid.UUID
	MFAPending  bool
	ActiveOrgID *uuid.UUID
	Principal   *auth.Principal
	TOTPEnabled bool
}

// NeedsTOTPEnrollment reports whether the user must enroll 2FA before doing
// anything else (spec §13.3: admins must use 2FA).
func (s *Session) NeedsTOTPEnrollment(require bool) bool {
	return require && s.Principal.IsSuperadmin && !s.TOTPEnabled
}

func (s *Service) createSession(ctx context.Context, q *db.Queries, userID uuid.UUID, mfaPending bool, activeOrg *uuid.UUID, m Meta) (*LoginResult, error) {
	plain, hash, err := auth.NewSessionToken()
	if err != nil {
		return nil, err
	}
	ttl := s.cfg.SessionIdle
	if mfaPending {
		ttl = s.cfg.MFAPendingTTL
	}
	exp := s.now().Add(ttl)
	ua := m.UserAgent
	if len(ua) > 512 {
		ua = ua[:512]
	}
	if err := q.CreateSession(ctx, db.CreateSessionParams{
		ID: newID(), UserID: userID, TokenHash: hash, MfaPending: mfaPending, ActiveOrgID: activeOrg,
		Ip: m.IP, UserAgent: ua, ExpiresAt: exp,
	}); err != nil {
		return nil, err
	}
	return &LoginResult{SessionToken: plain, MFAPending: mfaPending, UserID: userID, ExpiresAt: exp}, nil
}

// Login verifies e-mail and password. If the user has 2FA, the returned
// session is MFA-pending and only usable for VerifyMFA. Unknown e-mails,
// wrong passwords and locked accounts all return ErrInvalidCredentials so the
// response does not reveal which accounts exist.
func (s *Service) Login(ctx context.Context, email, password string, m Meta) (*LoginResult, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if !s.loginIP.Allow("ip:"+m.IP) || !s.loginID.Allow("id:"+email) {
		return nil, ErrRateLimited
	}
	var res *LoginResult
	// Failures are recorded (counter, lockout, audit) and the transaction is
	// committed; returning an error from inside would roll them back.
	failed := false
	err := s.db.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		u, err := q.GetUserByEmail(ctx, email)
		if err != nil {
			auth.VerifyDummy(password)
			if errors.Is(store.NotFound(err), store.ErrNotFound) {
				failed = true
				return audit(ctx, q, nil, nil, "login.failure", "user", "", m, map[string]any{"reason": "unknown_user"})
			}
			return err
		}
		ok, rehash, verr := auth.VerifyPassword(password, u.PasswordHash)
		if verr != nil {
			return verr
		}
		if u.LockedUntil != nil && u.LockedUntil.After(s.now()) {
			failed = true
			return audit(ctx, q, nil, &u.ID, "login.failure", "user", u.ID.String(), m, map[string]any{"reason": "locked"})
		}
		if !ok {
			if _, err := q.RecordLoginFailure(ctx, db.RecordLoginFailureParams{
				ID: u.ID, Threshold: int32(s.cfg.LockThreshold), LockMinutes: int32(s.cfg.LockMinutes), //nolint:gosec // small config ints
			}); err != nil {
				return err
			}
			failed = true
			return audit(ctx, q, nil, &u.ID, "login.failure", "user", u.ID.String(), m, map[string]any{"reason": "bad_password"})
		}
		if rehash {
			if h, err := auth.HashPassword(password); err == nil {
				_ = q.UpdateUserPassword(ctx, db.UpdateUserPasswordParams{ID: u.ID, PasswordHash: h})
			}
		}
		if err := q.RecordLoginSuccess(ctx, u.ID); err != nil {
			return err
		}
		res, err = s.createSession(ctx, q, u.ID, u.TotpEnabled, nil, m)
		if err != nil {
			return err
		}
		action := "login.success"
		if u.TotpEnabled {
			action = "login.password_ok_mfa_pending"
		}
		return audit(ctx, q, nil, &u.ID, action, "user", u.ID.String(), m, nil)
	})
	if err != nil {
		return nil, wrap("login", err)
	}
	if failed {
		return nil, ErrInvalidCredentials
	}
	return res, nil
}

// VerifyMFA completes a 2FA login: the pending session is destroyed and a
// fresh session token issued (session fixation protection).
func (s *Service) VerifyMFA(ctx context.Context, pendingToken, code string, m Meta) (*LoginResult, error) {
	sess, err := s.lookupSession(ctx, pendingToken)
	if err != nil || !sess.MFAPending {
		return nil, ErrUnauthorized
	}
	if !s.mfaTry.Allow(sess.ID.String()) {
		_ = s.db.Tx(ctx, store.Scope{}, func(q *db.Queries) error { return q.DeleteSession(ctx, sess.ID) })
		return nil, ErrRateLimited
	}
	var res *LoginResult
	failed := false
	err = s.db.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		u, err := q.GetUserByID(ctx, sess.Principal.UserID)
		if err != nil {
			return err
		}
		secret, err := s.box.Open(u.TotpSecretEnc, u.TotpNonce, totpAAD(u.ID))
		if err != nil {
			return err
		}
		step, ok := auth.VerifyTOTP(secret, code, s.now())
		if !ok || !s.replay.Use(u.ID.String(), step, s.now()) {
			failed = true
			return audit(ctx, q, nil, &u.ID, "login.mfa_failure", "user", u.ID.String(), m, nil)
		}
		if err := q.DeleteSession(ctx, sess.ID); err != nil {
			return err
		}
		res, err = s.createSession(ctx, q, u.ID, false, nil, m)
		if err != nil {
			return err
		}
		return audit(ctx, q, nil, &u.ID, "login.success", "user", u.ID.String(), m, map[string]any{"mfa": true})
	})
	if err != nil {
		return nil, wrap("verify mfa", err)
	}
	if failed {
		return nil, ErrInvalidCredentials
	}
	return res, nil
}

func totpAAD(user uuid.UUID) []byte { return []byte("totp:" + user.String()) }

// Authenticate resolves a session cookie. Expired or unknown sessions return
// ErrUnauthorized. The idle timeout is extended at most once per minute.
func (s *Service) Authenticate(ctx context.Context, token string) (*Session, error) {
	sess, err := s.lookupSession(ctx, token)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Service) lookupSession(ctx context.Context, token string) (*Session, error) {
	if token == "" || len(token) > 200 {
		return nil, ErrUnauthorized
	}
	var out *Session
	err := s.db.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		row, err := q.GetSessionByHash(ctx, auth.HashToken(token))
		if err != nil {
			return store.NotFound(err)
		}
		now := s.now()
		if now.Sub(row.CreatedAt) > s.cfg.SessionAbsolute || (row.LockedUntil != nil && row.LockedUntil.After(now)) {
			_ = q.DeleteSession(ctx, row.ID)
			return ErrUnauthorized
		}
		if !row.MfaPending && now.Sub(row.LastSeenAt) > time.Minute {
			if err := q.TouchSession(ctx, db.TouchSessionParams{ID: row.ID, ExpiresAt: now.Add(s.cfg.SessionIdle)}); err != nil {
				return err
			}
		}
		out = &Session{
			ID: row.ID, MFAPending: row.MfaPending, ActiveOrgID: row.ActiveOrgID, TOTPEnabled: row.TotpEnabled,
			Principal: &auth.Principal{
				UserID: row.UserID, Email: row.Email, Name: row.Name, Locale: row.Locale,
				IsSuperadmin: row.IsSuperadmin, SessionID: row.ID,
			},
		}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, ErrUnauthorized) {
		return nil, ErrUnauthorized
	}
	return out, wrap("session", err)
}

// Logout deletes the session.
func (s *Service) Logout(ctx context.Context, sess *Session, m Meta) error {
	return s.db.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		if err := q.DeleteSession(ctx, sess.ID); err != nil {
			return err
		}
		return audit(ctx, q, nil, &sess.Principal.UserID, "logout", "session", sess.ID.String(), m, nil)
	})
}

// SetActiveOrg remembers the org selected in the UI.
func (s *Service) SetActiveOrg(ctx context.Context, sess *Session, org uuid.UUID) error {
	return s.db.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		return q.SetSessionActiveOrg(ctx, db.SetSessionActiveOrgParams{ID: sess.ID, ActiveOrgID: &org})
	})
}

// AuthenticateToken resolves "Authorization: Bearer <token>". The token's
// user must still be a member of the token's organization.
func (s *Service) AuthenticateToken(ctx context.Context, token string) (*auth.Principal, error) {
	if !strings.HasPrefix(token, auth.PrefixPersonal) && !strings.HasPrefix(token, auth.PrefixCI) {
		return nil, ErrUnauthorized
	}
	var p *auth.Principal
	err := s.db.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		t, err := q.LookupAPIToken(ctx, auth.HashToken(token))
		if err != nil {
			return store.NotFound(err)
		}
		now := s.now()
		if !t.RevokedAt.IsZero() || (!t.ExpiresAt.IsZero() && t.ExpiresAt.Before(now)) || t.UserID == uuid.Nil {
			return ErrUnauthorized
		}
		u, err := q.GetUserByID(ctx, t.UserID)
		if err != nil {
			return err
		}
		p = &auth.Principal{
			UserID: u.ID, Email: u.Email, Name: u.Name, Locale: u.Locale, IsSuperadmin: false,
			TokenID: t.ID, TokenOrgID: t.OrgID, TokenScopes: t.Scopes,
		}
		return nil
	})
	if err != nil {
		return nil, ErrUnauthorized
	}
	// Membership check and last-used update run in the token's org scope.
	err = s.db.Tx(ctx, store.Scope{OrgID: p.TokenOrgID, UserID: p.UserID}, func(q *db.Queries) error {
		if _, err := q.GetMembership(ctx, db.GetMembershipParams{OrgID: p.TokenOrgID, UserID: p.UserID}); err != nil {
			return ErrUnauthorized
		}
		return q.TouchAPIToken(ctx, p.TokenID)
	})
	if err != nil {
		return nil, ErrUnauthorized
	}
	return p, nil
}

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}
