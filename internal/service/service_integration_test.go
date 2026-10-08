//go:build integration

package service

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/crypto"
	"github.com/ininia/scanx/internal/secret"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
	"github.com/ininia/scanx/internal/testdb"
)

var seq atomic.Int64

func uniq(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano()%1_000_000, seq.Add(1))
}

const goodPassword = "FAKE-correct-horse-battery-staple-9"

func newService(t *testing.T) (*Service, *store.DB) {
	t.Helper()
	admin, app := os.Getenv("SCANX_TEST_DATABASE_ADMIN_URL"), os.Getenv("SCANX_TEST_DATABASE_URL")
	if admin == "" || app == "" {
		t.Skip("SCANX_TEST_DATABASE_* not set; run via scripts/dev.sh test-integration")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := store.Migrate(ctx, secret.Secret(admin), log); err != nil {
		t.Fatal(err)
	}
	pool, err := store.Open(ctx, secret.Secret(app))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	box, err := crypto.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	d := &store.DB{Pool: pool}
	cfg := DefaultConfig()
	cfg.SetupToken = "FAKE-setup-token"
	return New(d, box, cfg, log), d
}

// newUser creates a regular user directly (bypassing setup) and logs in.
func newUser(t *testing.T, s *Service, d *store.DB, superadmin bool) (*Session, string) {
	t.Helper()
	ctx := context.Background()
	email := uniq("user") + "@example.test"
	hash, err := auth.HashPassword(goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		_, err := q.CreateUser(ctx, db.CreateUserParams{ID: newID(), Email: email, Name: "Test", PasswordHash: hash, IsSuperadmin: superadmin})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Login(ctx, email, goodPassword, Meta{IP: uniq("ip")})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.Authenticate(ctx, res.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	return sess, email
}

func newOrg(t *testing.T, s *Service, owner *Session) *OrgCtx {
	t.Helper()
	ctx := context.Background()
	s.cfg.AllowOrgCreation = true
	org, err := s.CreateOrg(ctx, owner.Principal, "Org "+uniq("o"), "", Meta{})
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.ResolveOrg(ctx, owner.Principal, org.Slug)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestLoginLockoutIsPersisted(t *testing.T) {
	s, d := newService(t)
	ctx := context.Background()
	_, email := newUser(t, s, d, false)
	s.cfg.LockThreshold = 3
	for i := 0; i < 3; i++ {
		if _, err := s.Login(ctx, email, "wrong-password-xyz", Meta{IP: uniq("ip")}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// Even the correct password is rejected while locked, with the same error.
	if _, err := s.Login(ctx, email, goodPassword, Meta{IP: uniq("ip")}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("locked account accepted: %v", err)
	}
	var failed int32
	var locked *time.Time
	_ = d.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		u, err := q.GetUserByEmail(ctx, email)
		failed, locked = u.FailedLogins, u.LockedUntil
		return err
	})
	if failed != 3 || locked == nil {
		t.Fatalf("failure counter not committed: failed=%d locked=%v", failed, locked)
	}
	if _, err := s.Login(ctx, "nobody-"+uniq("x")+"@example.test", goodPassword, Meta{IP: uniq("ip")}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user must look like a bad password: %v", err)
	}
}

func TestLoginRateLimitPerIP(t *testing.T) {
	s, d := newService(t)
	_, email := newUser(t, s, d, false)
	ip := uniq("ip")
	var last error
	for i := 0; i < 7; i++ {
		_, last = s.Login(context.Background(), email, "wrong-password-xyz", Meta{IP: ip})
	}
	if !errors.Is(last, ErrRateLimited) {
		t.Fatalf("want rate limit after 5/min, got %v", last)
	}
}

func TestMFAFlowAndReplay(t *testing.T) {
	s, d := newService(t)
	ctx := context.Background()
	sess, email := newUser(t, s, d, false)
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	enr, err := s.BeginTOTP(ctx, sess.Principal)
	if err != nil {
		t.Fatal(err)
	}
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enr.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmTOTP(ctx, sess.Principal, "000000", Meta{}); err == nil {
		t.Fatal("wrong code enabled 2FA")
	}
	code := auth.TOTPCode(secretBytes, now.Unix()/30)
	if err := s.ConfirmTOTP(ctx, sess.Principal, code, Meta{}); err != nil {
		t.Fatal(err)
	}

	res, err := s.Login(ctx, email, goodPassword, Meta{IP: uniq("ip")})
	if err != nil || !res.MFAPending {
		t.Fatalf("2FA user must get a pending session: %+v %v", res, err)
	}
	pending, _ := s.Authenticate(ctx, res.SessionToken)
	if pending == nil || !pending.MFAPending {
		t.Fatal("pending session expected")
	}
	// Replaying the enrollment code must fail; the next step's code works.
	if _, err := s.VerifyMFA(ctx, res.SessionToken, code, Meta{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("replayed code accepted: %v", err)
	}
	now = now.Add(30 * time.Second)
	full, err := s.VerifyMFA(ctx, res.SessionToken, auth.TOTPCode(secretBytes, now.Unix()/30), Meta{})
	if err != nil || full.MFAPending || full.SessionToken == res.SessionToken {
		t.Fatalf("mfa: %+v %v", full, err)
	}
	if _, err := s.Authenticate(ctx, res.SessionToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("pending session must be destroyed after MFA (fixation)")
	}
}

func TestTenantIsolation(t *testing.T) {
	s, d := newService(t)
	ctx := context.Background()
	alice, _ := newUser(t, s, d, false)
	bob, bobEmail := newUser(t, s, d, false)
	orgA := newOrg(t, s, alice)
	orgB := newOrg(t, s, bob)
	pa, err := s.CreateProject(ctx, orgA, ProjectInput{RepoURL: "git@github.com:acme/" + uniq("a") + ".git"}, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject(ctx, orgB, ProjectInput{RepoURL: "git@github.com:bob/" + uniq("b") + ".git"}, Meta{}); err != nil {
		t.Fatal(err)
	}

	// Bob cannot resolve Alice's org at all → 404, not 403.
	if _, err := s.ResolveOrg(ctx, bob.Principal, orgA.Org.Slug); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant org: %v", err)
	}
	// RLS: a query running in org B's scope cannot see org A's rows even when
	// it asks for them by primary key.
	err = d.Tx(ctx, store.Scope{OrgID: orgB.Org.ID, UserID: bob.Principal.UserID}, func(q *db.Queries) error {
		_, err := q.GetProjectByID(ctx, pa.ID)
		return store.NotFound(err)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RLS let org B read org A project: %v", err)
	}
	myOrgs, err := s.ListMyOrgs(ctx, bob.Principal)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range myOrgs {
		if o.ID == orgA.Org.ID {
			t.Fatal("bob lists alice's org")
		}
	}
	// Alice invites nobody; adding bob by e-mail makes the org visible.
	if err := s.AddExistingMember(ctx, orgA, bobEmail, "viewer", Meta{}); err != nil {
		t.Fatal(err)
	}
	ob, err := s.ResolveOrg(ctx, bob.Principal, orgA.Org.Slug)
	if err != nil || ob.Role != auth.RoleViewer {
		t.Fatalf("after membership: %+v %v", ob, err)
	}
	if _, err := s.CreateProject(ctx, ob, ProjectInput{RepoURL: "git@github.com:x/y.git"}, Meta{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer created a project: %v", err)
	}
}

func TestLastOwnerAndRoleGrants(t *testing.T) {
	s, d := newService(t)
	ctx := context.Background()
	alice, _ := newUser(t, s, d, false)
	bob, bobEmail := newUser(t, s, d, false)
	o := newOrg(t, s, alice)
	if err := s.RemoveMember(ctx, o, alice.Principal.UserID, Meta{}); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("last owner removed: %v", err)
	}
	if err := s.AddExistingMember(ctx, o, bobEmail, "admin", Meta{}); err != nil {
		t.Fatal(err)
	}
	ob, _ := s.ResolveOrg(ctx, bob.Principal, o.Org.Slug)
	if err := s.UpdateMemberRole(ctx, ob, bob.Principal.UserID, "owner", Meta{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin promoted self to owner: %v", err)
	}
	if err := s.UpdateMemberRole(ctx, ob, alice.Principal.UserID, "viewer", Meta{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin demoted the owner: %v", err)
	}
	if err := s.AddExistingMember(ctx, o, bobEmail, "viewer", Meta{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate membership: %v", err)
	}
}

func TestInvitationFlow(t *testing.T) {
	s, d := newService(t)
	ctx := context.Background()
	alice, _ := newUser(t, s, d, false)
	o := newOrg(t, s, alice)
	email := uniq("invitee") + "@example.test"
	inv, err := s.Invite(ctx, o, email, "member", Meta{})
	if err != nil || !strings.HasPrefix(inv.Token, auth.PrefixInvite) {
		t.Fatalf("invite: %+v %v", inv, err)
	}
	info, err := s.LookupInvitation(ctx, inv.Token)
	if err != nil || info.UserExists || info.Email != email {
		t.Fatalf("lookup: %+v %v", info, err)
	}
	if _, err := s.AcceptInvitation(ctx, inv.Token, nil, "New Person", "short", Meta{}); err == nil {
		t.Fatal("weak password accepted")
	}
	res, err := s.AcceptInvitation(ctx, inv.Token, nil, "New Person", goodPassword, Meta{})
	if err != nil || res == nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := s.LookupInvitation(ctx, inv.Token); !errors.Is(err, ErrNotFound) {
		t.Fatal("invitation reusable after acceptance")
	}
	sess, _ := s.Authenticate(ctx, res.SessionToken)
	oc, err := s.ResolveOrg(ctx, sess.Principal, o.Org.Slug)
	if err != nil || oc.Role != auth.RoleMember {
		t.Fatalf("joined org: %+v %v", oc, err)
	}
	if _, err := s.LookupInvitation(ctx, "scanx_inv_doesnotexist"); !errors.Is(err, ErrNotFound) {
		t.Fatal("bogus invitation found")
	}
}

func TestAPITokens(t *testing.T) {
	s, d := newService(t)
	ctx := context.Background()
	alice, _ := newUser(t, s, d, false)
	o := newOrg(t, s, alice)
	other := newOrg(t, s, alice)
	tok, err := s.CreateAPIToken(ctx, o, "ci", []string{"read"}, 30, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.AuthenticateToken(ctx, tok.Token)
	if err != nil || p.TokenOrgID != o.Org.ID || p.HasScope("write") {
		t.Fatalf("token principal: %+v %v", p, err)
	}
	if _, err := s.ResolveOrg(ctx, p, other.Org.Slug); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token reached another org: %v", err)
	}
	oc, err := s.ResolveOrg(ctx, p, o.Org.Slug)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProject(ctx, oc, ProjectInput{RepoURL: "git@github.com:a/b.git"}, Meta{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("read-only token wrote: %v", err)
	}
	if _, err := s.CreateAPIToken(ctx, oc, "x", nil, 0, Meta{}); !errors.Is(err, ErrForbidden) {
		t.Fatal("token minted a token")
	}
	if err := s.RevokeAPIToken(ctx, o, tok.ID, Meta{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateToken(ctx, tok.Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked token still works")
	}
	if _, err := s.AuthenticateToken(ctx, "scanx_pat_"+strings.Repeat("A", 40)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("unknown token accepted")
	}
	logs, err := s.ListAudit(ctx, o, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]bool{}
	for _, l := range logs {
		actions[l.Action] = true
	}
	for _, want := range []string{"org.created", "token.created", "token.revoked"} {
		if !actions[want] {
			t.Errorf("audit missing %s (have %v)", want, actions)
		}
	}
}

func TestAuditLogIsAppendOnly(t *testing.T) {
	_, d := newService(t)
	ctx := context.Background()
	err := d.Tx(ctx, store.Scope{Superadmin: true}, func(q *db.Queries) error {
		_, err := d.Pool.Exec(ctx, `DELETE FROM audit_logs`)
		return err
	})
	if err == nil {
		t.Fatal("app role could delete audit logs")
	}
}

func TestSetupWizard(t *testing.T) {
	adminURL, appURL := testdb.Fresh(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := store.Migrate(ctx, adminURL, log); err != nil {
		t.Fatal(err)
	}
	pool, err := store.Open(ctx, appURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	box, _ := crypto.New(bytes.Repeat([]byte{9}, 32))
	cfg := DefaultConfig()
	cfg.SetupToken = "FAKE-setup-token"
	s := New(&store.DB{Pool: pool}, box, cfg, log)
	now := time.Now()
	s.SetClock(func() time.Time { return now })

	st, err := s.SetupState(ctx)
	if err != nil || st.Completed || st.HasAdmin {
		t.Fatalf("fresh state: %+v %v", st, err)
	}
	if err := s.CheckSetupToken(ctx, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong token: %v", err)
	}
	if err := s.CheckSetupToken(ctx, " FAKE-setup-token "); err != nil {
		t.Fatal(err)
	}
	res, err := s.CreateFirstAdmin(ctx, "admin@example.test", "Admin", goodPassword, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateFirstAdmin(ctx, "second@example.test", "Second", goodPassword, Meta{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second admin: %v", err)
	}
	sess, err := s.Authenticate(ctx, res.SessionToken)
	if err != nil || !sess.Principal.IsSuperadmin {
		t.Fatalf("admin session: %+v %v", sess, err)
	}
	if !sess.NeedsTOTPEnrollment(true) {
		t.Fatal("admin must be forced to enroll 2FA")
	}
	if err := s.CompleteSetup(ctx, sess, Meta{}); err == nil {
		t.Fatal("setup completed without 2FA/settings/org")
	}
	enr, err := s.BeginTOTP(ctx, sess.Principal)
	if err != nil {
		t.Fatal(err)
	}
	sec, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enr.Secret)
	if err := s.ConfirmTOTP(ctx, sess.Principal, auth.TOTPCode(sec, now.Unix()/30), Meta{}); err != nil {
		t.Fatal(err)
	}
	sess, _ = s.Authenticate(ctx, res.SessionToken)
	bad := InstanceSettings{Name: "scanX", BaseURL: "javascript:alert(1)", DefaultLocale: "tr", Timezone: "Europe/Istanbul"}
	if err := s.SaveInstanceSettings(ctx, sess.Principal, bad, Meta{}); err == nil {
		t.Fatal("invalid base URL accepted")
	}
	good := InstanceSettings{Name: "ACME scanX", BaseURL: "https://scan.example.test/", DefaultLocale: "tr", Timezone: "Europe/Istanbul"}
	if err := s.SaveInstanceSettings(ctx, sess.Principal, good, Meta{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOrg(ctx, sess.Principal, "ACME Yazılım", "", Meta{}); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteSetup(ctx, sess, Meta{}); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSetupToken(ctx, "FAKE-setup-token"); !errors.Is(err, ErrSetupCompleted) {
		t.Fatalf("setup token must be dead after completion: %v", err)
	}
	in, _ := s.Instance(ctx)
	if in.BaseURL != "https://scan.example.test" || in.Name != "ACME scanX" {
		t.Fatalf("instance %+v", in)
	}
	orgs, _ := s.ListMyOrgs(ctx, sess.Principal)
	if len(orgs) != 1 || orgs[0].Slug != "acme-yazilim" || orgs[0].Role != auth.RoleOwner {
		t.Fatalf("orgs %+v", orgs)
	}
}
