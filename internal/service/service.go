// Package service holds scanX business logic shared by the JSON API and the
// web UI: setup, authentication, organizations, members, tokens, projects
// and the audit log. Every org-scoped operation runs inside a tenant-scoped
// transaction (row-level security) in addition to explicit checks here.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/crypto"
	"github.com/ininia/scanx/internal/notify"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
)

// Errors mapped to HTTP status codes by the transport layers.
var (
	ErrNotFound           = store.ErrNotFound
	ErrForbidden          = errors.New("forbidden")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrInvalidCredentials = errors.New("invalid_credentials")
	ErrMFARequired        = errors.New("mfa_required")
	ErrRateLimited        = errors.New("rate_limited")
	ErrConflict           = errors.New("conflict")
	ErrSetupCompleted     = errors.New("setup_completed")
	ErrLastOwner          = errors.New("last_owner")
)

// ValidationError reports an invalid input field with a stable code.
type ValidationError struct {
	Field string
	Code  string
}

func (e *ValidationError) Error() string { return e.Field + ": " + e.Code }

func invalid(field, code string) error { return &ValidationError{Field: field, Code: code} }

// Config tunes the service.
type Config struct {
	SessionIdle      time.Duration // spec: 12h idle timeout
	SessionAbsolute  time.Duration
	MFAPendingTTL    time.Duration
	LockThreshold    int
	LockMinutes      int
	InvitationTTL    time.Duration
	SetupToken       string
	RequireAdmin2FA  bool
	AllowOrgCreation bool // non-superadmins may create orgs (SaaS mode)
	Issuer           string
}

// DefaultConfig returns spec defaults.
func DefaultConfig() Config {
	return Config{
		SessionIdle:     12 * time.Hour,
		SessionAbsolute: 7 * 24 * time.Hour,
		MFAPendingTTL:   5 * time.Minute,
		LockThreshold:   10,
		LockMinutes:     15,
		InvitationTTL:   7 * 24 * time.Hour,
		RequireAdmin2FA: true,
		Issuer:          "scanX",
	}
}

// Service is the application core.
type Service struct {
	db      *store.DB
	box     *crypto.Box
	cfg     Config
	now     func() time.Time
	log     *slog.Logger
	replay  *auth.ReplayGuard
	loginIP *auth.Limiter
	loginID *auth.Limiter
	mfaTry  *auth.Limiter

	notifier *notify.Sender
}

// New creates a Service.
func New(d *store.DB, box *crypto.Box, cfg Config, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		db: d, box: box, cfg: cfg, now: time.Now, log: log,
		replay:  auth.NewReplayGuard(),
		loginIP: auth.NewLimiter(5, time.Minute, 5),      // spec §5.3: login 5/min/IP
		loginID: auth.NewLimiter(10, 15*time.Minute, 10), // per account
		mfaTry:  auth.NewLimiter(5, 5*time.Minute, 5),    // per pending session
	}
}

// SetClock overrides the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Meta carries request metadata for auditing.
type Meta struct {
	IP        string
	UserAgent string
}

// audit writes an audit log entry inside the caller's transaction.
func audit(ctx context.Context, q *db.Queries, org, user *uuid.UUID, action, targetType, targetID string, m Meta, md map[string]any) error {
	raw := json.RawMessage(`{}`)
	if len(md) > 0 {
		b, err := json.Marshal(md)
		if err != nil {
			return err
		}
		raw = b
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	return q.InsertAuditLog(ctx, db.InsertAuditLogParams{
		ID: id, OrgID: org, UserID: user, Action: action, TargetType: targetType, TargetID: targetID,
		Ip: m.IP, Metadata: raw,
	})
}

func ptr[T any](v T) *T { return &v }

func newID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New()
	}
	return id
}

// --- validation helpers ---

func cleanEmail(e string) (string, error) {
	e = strings.TrimSpace(strings.ToLower(e))
	if len(e) < 3 || len(e) > 320 {
		return "", invalid("email", "invalid")
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || !strings.Contains(e[strings.LastIndex(e, "@"):], ".") {
		return "", invalid("email", "invalid")
	}
	return e, nil
}

func cleanName(field, n string, min, max int) (string, error) {
	n = strings.TrimSpace(n)
	l := len([]rune(n))
	if l < min || l > max {
		return "", invalid(field, "length")
	}
	for _, r := range n {
		if unicode.IsControl(r) {
			return "", invalid(field, "invalid")
		}
	}
	return n, nil
}

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

var trMap = strings.NewReplacer("ç", "c", "ğ", "g", "ı", "i", "ö", "o", "ş", "s", "ü", "u", "â", "a", "î", "i", "û", "u")

// Slugify derives a URL slug from a display name.
func Slugify(name string) string {
	s := trMap.Replace(strings.ToLower(strings.TrimSpace(name)))
	var b strings.Builder
	dash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	return out
}

func validSlug(s string) error {
	if !slugRe.MatchString(s) {
		return invalid("slug", "invalid")
	}
	return nil
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	var ve *ValidationError
	if errors.As(err, &ve) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrForbidden) ||
		errors.Is(err, ErrConflict) || errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrLastOwner) {
		return err
	}
	return fmt.Errorf("%s: %w", op, err)
}
