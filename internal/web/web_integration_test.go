//go:build integration

package web_test

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ininia/scanx/internal/app"
	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/config"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/testdb"
)

const adminPassword = "correct-horse-battery-staple-9"

type browser struct {
	t    *testing.T
	base string
	c    *http.Client
}

var (
	csrfRe   = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	secretRe = regexp.MustCompile(`<div class="secret-box">([A-Z2-7]+)</div>`)
)

func (b *browser) get(path string, want int) (string, *http.Response) {
	b.t.Helper()
	resp, err := b.c.Get(b.base + path)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		b.t.Fatalf("GET %s: %d want %d\n%s", path, resp.StatusCode, want, body)
	}
	return string(body), resp
}

// post submits a form, taking the CSRF token from the page at from.
func (b *browser) post(from, path string, form url.Values, want int) (string, *http.Response) {
	b.t.Helper()
	page, _ := b.get(from, 200)
	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		b.t.Fatalf("no csrf token on %s", from)
	}
	form.Set("csrf_token", html.UnescapeString(m[1]))
	return b.postRaw(path, form, want)
}

func (b *browser) postRaw(path string, form url.Values, want int) (string, *http.Response) {
	b.t.Helper()
	req, _ := http.NewRequest("POST", b.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.base)
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		b.t.Fatalf("POST %s: %d want %d\n%s", path, resp.StatusCode, want, body)
	}
	return string(body), resp
}

func totp(t *testing.T, secret string, offset int64) string {
	t.Helper()
	sec, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return auth.TOTPCode(sec, time.Now().Unix()/30+offset)
}

func TestSetupWizardLoginAndProjects(t *testing.T) {
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
	cfg, err := config.LoadFrom(map[string]string{
		"SCANX_MASTER_KEY":  base64.StdEncoding.EncodeToString([]byte("FAKE-0123456789abcdef0123456789a")),
		"SCANX_SESSION_KEY": "FAKE-session-key-0123456789abcdef0123",
		"SCANX_SETUP_TOKEN": "FAKE-1234-5678-9abc",
		"SCANX_BASE_URL":    "http://localhost",
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := app.BuildHandler(cfg, pool, log)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	b := &browser{t: t, base: ts.URL, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}

	// Everything redirects to the wizard until setup completes.
	_, resp := b.get("/", http.StatusSeeOther)
	if resp.Header.Get("Location") != "/setup" {
		t.Fatalf("redirect %s", resp.Header.Get("Location"))
	}
	page, _ := b.get("/setup", 200)
	if !strings.Contains(page, `action="/setup/token"`) {
		t.Fatal("token step expected")
	}
	b.post("/setup", "/setup/token", url.Values{"token": {"wrong"}}, http.StatusUnauthorized)
	b.post("/setup", "/setup/token", url.Values{"token": {"FAKE-1234-5678-9abc"}}, http.StatusSeeOther)

	b.post("/setup", "/setup/admin", url.Values{"name": {"Ayşe Admin"}, "email": {"admin@example.test"}, "password": {adminPassword}, "password2": {"different-password-xyz"}}, http.StatusUnprocessableEntity)
	b.post("/setup", "/setup/admin", url.Values{"name": {"Ayşe Admin"}, "email": {"admin@example.test"}, "password": {"short"}, "password2": {"short"}}, http.StatusUnprocessableEntity)
	b.post("/setup", "/setup/admin", url.Values{"name": {"Ayşe Admin"}, "email": {"admin@example.test"}, "password": {adminPassword}, "password2": {adminPassword}}, http.StatusSeeOther)

	page, _ = b.get("/setup", 200)
	m := secretRe.FindStringSubmatch(page)
	if m == nil || !strings.Contains(page, `src="data:image/png;base64,`) {
		t.Fatalf("2FA step with QR expected:\n%s", page)
	}
	secret := m[1]
	// The app is unusable until 2FA is enrolled.
	if _, r := b.get("/admin", http.StatusSeeOther); r.Header.Get("Location") != "/setup" {
		t.Fatalf("admin page reachable before setup: %s", r.Header.Get("Location"))
	}
	b.post("/setup", "/setup/2fa", url.Values{"code": {"000000"}}, http.StatusUnprocessableEntity)
	b.post("/setup", "/setup/2fa", url.Values{"code": {totp(t, secret, 0)}}, http.StatusSeeOther)

	b.post("/setup", "/setup/instance", url.Values{"name": {"ACME scanX"}, "base_url": {"ftp://x"}, "default_locale": {"tr"}, "timezone": {"Europe/Istanbul"}}, http.StatusUnprocessableEntity)
	b.post("/setup", "/setup/instance", url.Values{"name": {"ACME scanX"}, "base_url": {ts.URL}, "default_locale": {"tr"}, "timezone": {"Europe/Istanbul"}}, http.StatusSeeOther)
	b.post("/setup", "/setup/org", url.Values{"name": {"ACME Yazılım"}}, http.StatusSeeOther)
	page, _ = b.get("/setup", 200)
	if !strings.Contains(page, "ACME Yazılım") || !strings.Contains(page, "admin@example.test") {
		t.Fatalf("summary expected:\n%s", page)
	}
	_, resp = b.post("/setup", "/setup/complete", url.Values{}, http.StatusSeeOther)
	if !strings.HasPrefix(resp.Header.Get("Location"), "/?msg=flash.setup_done") {
		t.Fatalf("complete redirect %s", resp.Header.Get("Location"))
	}
	b.get("/setup", http.StatusNotFound) // the wizard is gone for good
	_, resp = b.get("/", http.StatusSeeOther)
	if resp.Header.Get("Location") != "/o/acme-yazilim" {
		t.Fatalf("home redirect %s", resp.Header.Get("Location"))
	}
	page, _ = b.get("/o/acme-yazilim", 200)
	if !strings.Contains(page, "ACME Yazılım") || !strings.Contains(page, "scanx-mark.svg") {
		t.Fatal("dashboard expected")
	}

	// Projects: validation, creation, escaping.
	b.post("/o/acme-yazilim/projects/new", "/o/acme-yazilim/projects/new", url.Values{"repo_url": {"file:///etc/passwd"}}, http.StatusUnprocessableEntity)
	_, resp = b.post("/o/acme-yazilim/projects/new", "/o/acme-yazilim/projects/new",
		url.Values{"repo_url": {"git@github.com:acme/shop.git"}, "name": {`Shop <script>alert(1)</script>`}, "branches": {"main, release"}}, http.StatusSeeOther)
	loc := resp.Header.Get("Location")
	page, _ = b.get(loc, 200)
	if strings.Contains(page, "<script>alert(1)") || !strings.Contains(page, "&lt;script&gt;") {
		t.Fatal("project name not escaped")
	}
	page, _ = b.get("/o/acme-yazilim/projects", 200)
	if !strings.Contains(page, "git@github.com:acme/shop.git") {
		t.Fatal("project list")
	}
	b.get("/o/no-such-org", http.StatusNotFound)

	// Tokens and members pages.
	page, _ = b.post("/o/acme-yazilim/tokens", "/o/acme-yazilim/tokens", url.Values{"name": {"ci"}, "scope": {"read"}, "days": {"30"}}, 200)
	if !regexp.MustCompile(`scanx_pat_[0-9A-Za-z]{40}`).MatchString(page) {
		t.Fatal("token not shown once")
	}
	page, _ = b.post("/o/acme-yazilim/members", "/o/acme-yazilim/members/invite", url.Values{"email": {"dev@example.test"}, "role": {"member"}}, 200)
	if !strings.Contains(page, "/invite/scanx_inv_") {
		t.Fatal("invitation link not shown")
	}
	b.get("/o/acme-yazilim/audit", 200)
	b.get("/admin", 200)

	// CSRF: a form post without a token is rejected.
	b.postRaw("/o/acme-yazilim/projects/new", url.Values{"repo_url": {"git@github.com:x/y.git"}}, http.StatusForbidden)

	// Logout, then log in again with 2FA; next=//evil is neutralised.
	b.post("/account", "/logout", url.Values{}, http.StatusSeeOther)
	b.get("/o/acme-yazilim", http.StatusSeeOther)
	b.post("/login", "/login", url.Values{"email": {"admin@example.test"}, "password": {"wrong-password-123"}, "next": {"//evil.example"}}, http.StatusUnauthorized)
	_, resp = b.post("/login", "/login", url.Values{"email": {"admin@example.test"}, "password": {adminPassword}, "next": {"//evil.example"}}, http.StatusSeeOther)
	if !strings.HasPrefix(resp.Header.Get("Location"), "/login/2fa") {
		t.Fatalf("2FA step expected, got %s", resp.Header.Get("Location"))
	}
	b.get("/o/acme-yazilim", http.StatusSeeOther) // pending session is not logged in
	_, resp = b.post("/login/2fa", "/login/2fa?next=/", url.Values{"code": {totp(t, secret, 1)}}, http.StatusSeeOther)
	if resp.Header.Get("Location") != "/" {
		t.Fatalf("after 2FA: %s", resp.Header.Get("Location"))
	}
	b.get("/o/acme-yazilim", 200)

	// Language switch.
	b.get("/lang/en?next=/o/acme-yazilim", http.StatusSeeOther)
	page, _ = b.get("/o/acme-yazilim/projects", 200)
	if !strings.Contains(page, "Add project") {
		t.Fatal("English UI expected")
	}
}
