package service

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// Instance settings keys.
const (
	settingSetupCompleted = "setup_completed"
	settingInstance       = "instance"
)

// InstanceSettings are configured in the setup wizard (spec §13.3 step 3).
type InstanceSettings struct {
	Name          string `json:"name"`
	BaseURL       string `json:"base_url"`
	DefaultLocale string `json:"default_locale"`
	Timezone      string `json:"timezone"`
}

// SetupState tells the wizard where it is.
type SetupState struct {
	Completed   bool
	HasAdmin    bool
	HasOrg      bool
	HasSettings bool
}

// SetupState reports progress of the first-run wizard.
func (s *Service) SetupState(ctx context.Context) (SetupState, error) {
	var st SetupState
	err := s.db.Tx(ctx, store.Scope{Superadmin: true}, func(q *db.Queries) error {
		v, err := q.GetSetting(ctx, settingSetupCompleted)
		if err == nil {
			_ = json.Unmarshal(v, &st.Completed)
		} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return err
		}
		n, err := q.CountUsers(ctx)
		if err != nil {
			return err
		}
		st.HasAdmin = n > 0
		if _, err := q.GetSetting(ctx, settingInstance); err == nil {
			st.HasSettings = true
		}
		orgs, err := q.ListAllOrgs(ctx, db.ListAllOrgsParams{Limit: 1, Offset: 0})
		if err != nil {
			return err
		}
		st.HasOrg = len(orgs) > 0
		return nil
	})
	return st, wrap("setup state", err)
}

// CheckSetupToken compares the presented token with SCANX_SETUP_TOKEN in
// constant time. It always fails once setup has completed.
func (s *Service) CheckSetupToken(ctx context.Context, token string) error {
	st, err := s.SetupState(ctx)
	if err != nil {
		return err
	}
	if st.Completed {
		return ErrSetupCompleted
	}
	want := strings.TrimSpace(s.cfg.SetupToken)
	got := strings.TrimSpace(token)
	if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

// SetupTokenValue returns the configured setup token (for deriving proofs).
func (s *Service) SetupTokenValue() string { return strings.TrimSpace(s.cfg.SetupToken) }

// SetupProof is an HMAC binding a browser to a successfully entered setup
// token, so later wizard steps need not resend it.
func SetupProof(key []byte, setupToken string) string {
	return auth.CSRFToken(key, "setup:"+strings.TrimSpace(setupToken))
}

// CreateFirstAdmin creates the superadmin account. It only works while no
// user exists (serialized with an advisory lock) and setup is incomplete.
func (s *Service) CreateFirstAdmin(ctx context.Context, email, name, password string, m Meta) (*LoginResult, error) {
	email, err := cleanEmail(email)
	if err != nil {
		return nil, err
	}
	name, err = cleanName("name", name, 1, 200)
	if err != nil {
		return nil, err
	}
	if err := auth.ValidatePassword(password, email); err != nil {
		return nil, invalid("password", err.Error())
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}
	var res *LoginResult
	err = s.db.Tx(ctx, store.Scope{Superadmin: true}, func(q *db.Queries) error {
		if err := q.LockSetup(ctx); err != nil {
			return err
		}
		if v, err := q.GetSetting(ctx, settingSetupCompleted); err == nil && string(v) == "true" {
			return ErrSetupCompleted
		}
		n, err := q.CountUsers(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return ErrConflict
		}
		u, err := q.CreateUser(ctx, db.CreateUserParams{ID: newID(), Email: email, Name: name, PasswordHash: hash, IsSuperadmin: true})
		if err != nil {
			return err
		}
		if err := audit(ctx, q, nil, &u.ID, "setup.admin_created", "user", u.ID.String(), m, nil); err != nil {
			return err
		}
		res, err = s.createSession(ctx, q, u.ID, false, nil, m)
		return err
	})
	return res, wrap("create admin", err)
}

// SaveInstanceSettings stores wizard step 3.
func (s *Service) SaveInstanceSettings(ctx context.Context, p *auth.Principal, in InstanceSettings, m Meta) error {
	if !p.IsSuperadmin {
		return ErrForbidden
	}
	name, err := cleanName("name", in.Name, 1, 100)
	if err != nil {
		return err
	}
	in.Name = name
	if u, err := url.Parse(strings.TrimSpace(in.BaseURL)); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return invalid("base_url", "invalid")
	}
	in.BaseURL = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	if in.DefaultLocale != "tr" && in.DefaultLocale != "en" {
		return invalid("default_locale", "invalid")
	}
	if _, err := time.LoadLocation(in.Timezone); err != nil || in.Timezone == "" {
		return invalid("timezone", "invalid")
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return wrap("instance settings", s.db.Tx(ctx, store.Scope{UserID: p.UserID, Superadmin: true}, func(q *db.Queries) error {
		if err := q.UpsertSetting(ctx, db.UpsertSettingParams{Key: settingInstance, Value: raw}); err != nil {
			return err
		}
		return audit(ctx, q, nil, &p.UserID, "settings.instance_updated", "instance", "", m, nil)
	}))
}

// Instance returns instance settings (zero value if not configured).
func (s *Service) Instance(ctx context.Context) (InstanceSettings, error) {
	var in InstanceSettings
	err := s.db.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		v, err := q.GetSetting(ctx, settingInstance)
		if err != nil {
			return store.NotFound(err)
		}
		return json.Unmarshal(v, &in)
	})
	if errors.Is(err, store.ErrNotFound) {
		return InstanceSettings{Name: "scanX", DefaultLocale: "tr", Timezone: "Europe/Istanbul"}, nil
	}
	return in, wrap("instance", err)
}

// CompleteSetup finishes the wizard. Requirements: admin with 2FA (when
// required), instance settings and at least one organization.
func (s *Service) CompleteSetup(ctx context.Context, sess *Session, m Meta) error {
	if !sess.Principal.IsSuperadmin {
		return ErrForbidden
	}
	if sess.NeedsTOTPEnrollment(s.cfg.RequireAdmin2FA) {
		return invalid("totp", "required")
	}
	st, err := s.SetupState(ctx)
	if err != nil {
		return err
	}
	if st.Completed {
		return ErrSetupCompleted
	}
	if !st.HasSettings {
		return invalid("instance", "required")
	}
	if !st.HasOrg {
		return invalid("org", "required")
	}
	uid := sess.Principal.UserID
	return wrap("complete setup", s.db.Tx(ctx, store.Scope{UserID: uid, Superadmin: true}, func(q *db.Queries) error {
		if err := q.UpsertSetting(ctx, db.UpsertSettingParams{Key: settingSetupCompleted, Value: []byte("true")}); err != nil {
			return err
		}
		return audit(ctx, q, nil, &uid, "setup.completed", "instance", "", m, nil)
	}))
}
