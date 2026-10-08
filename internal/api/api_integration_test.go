//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
	"github.com/google/uuid"

	apispec "github.com/ininia/scanx/api"
	"github.com/ininia/scanx/internal/auth"
	"github.com/ininia/scanx/internal/crypto"
	"github.com/ininia/scanx/internal/server"
	"github.com/ininia/scanx/internal/service"
	"github.com/ininia/scanx/internal/store"
	"github.com/ininia/scanx/internal/store/db"
	"github.com/ininia/scanx/internal/testdb"
)

const password = "FAKE-correct-horse-battery-staple-9"

var csrfKey = []byte("FAKE-csrf-key-for-tests-0123456789")

type env struct {
	t      *testing.T
	ts     *httptest.Server
	svc    *service.Service
	d      *store.DB
	router routers.Router
}

func setup(t *testing.T) *env {
	t.Helper()
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
	t.Cleanup(pool.Close)
	box, _ := crypto.New(bytes.Repeat([]byte{3}, 32))
	d := &store.DB{Pool: pool}
	cfg := service.DefaultConfig()
	cfg.AllowOrgCreation = true
	svc := service.New(d, box, cfg, log)
	cookies := server.NewCookies(false)
	h := &Handler{Svc: svc, Cookies: cookies}
	handler := server.New(server.Options{
		API:        h.Mount,
		Middleware: []func(http.Handler) http.Handler{server.Authenticate(svc, cookies), server.CSRF(csrfKey, cookies)},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(apispec.OpenAPI)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(ctx); err != nil {
		t.Fatalf("openapi.yaml invalid: %v", err)
	}
	doc.Servers = openapi3.Servers{{URL: ts.URL + "/api/v1"}}
	rt, err := legacy.NewRouter(doc)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, ts: ts, svc: svc, d: d, router: rt}
}

// user creates a user, logs in via the API and returns an authenticated client.
func (e *env) user(name string) (*client, string) {
	e.t.Helper()
	email := fmt.Sprintf("%s-%d@example.test", name, time.Now().UnixNano())
	hash, _ := auth.HashPassword(password)
	ctx := context.Background()
	if err := e.d.Tx(ctx, store.Scope{}, func(q *db.Queries) error {
		_, err := q.CreateUser(ctx, db.CreateUserParams{ID: uuid.Must(uuid.NewV7()), Email: email, Name: name, PasswordHash: hash})
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	c := &client{e: e, http: &http.Client{Jar: jar}}
	resp := c.do("POST", "/auth/login", map[string]string{"email": email, "password": password}, 200)
	if !strings.Contains(resp, `"mfa_required":false`) {
		e.t.Fatalf("login: %s", resp)
	}
	return c, email
}

type client struct {
	e      *env
	http   *http.Client
	bearer string
}

func (c *client) withToken(tok string) *client {
	return &client{e: c.e, http: &http.Client{}, bearer: tok}
}

// do sends a request, checks the status and validates the response against
// the OpenAPI contract.
func (c *client) do(method, path string, body any, want int) string {
	c.e.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.e.ts.URL+"/api/v1"+path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	} else if c.http.Jar != nil {
		u, _ := url.Parse(c.e.ts.URL)
		for _, ck := range c.http.Jar.Cookies(u) {
			if ck.Name == "scanx_csrf" {
				req.Header.Set("X-CSRF-Token", auth.CSRFToken(csrfKey, ck.Value))
			}
		}
		if method != "GET" && req.Header.Get("X-CSRF-Token") == "" && path != "/auth/login" {
			// Prime the CSRF cookie like a browser loading a page first.
			c.do("GET", "/me", nil, 0)
			return c.do(method, path, body, want)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if want != 0 && resp.StatusCode != want {
		c.e.t.Fatalf("%s %s: status %d want %d: %s", method, path, resp.StatusCode, want, data)
	}
	if want != 0 {
		c.e.validate(req, resp, data)
	}
	return string(data)
}

func (e *env) validate(req *http.Request, resp *http.Response, body []byte) {
	e.t.Helper()
	route, params, err := e.router.FindRoute(req)
	if err != nil {
		e.t.Fatalf("route not in openapi.yaml: %s %s: %v", req.Method, req.URL.Path, err)
	}
	in := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: req, PathParams: params, Route: route,
			Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
		},
		Status: resp.StatusCode,
		Header: resp.Header,
	}
	in.SetBodyBytes(body)
	if err := openapi3filter.ValidateResponse(context.Background(), in); err != nil {
		e.t.Fatalf("contract violation %s %s %d: %v\nbody: %s", req.Method, req.URL.Path, resp.StatusCode, err, body)
	}
}

func decodeJSON[T any](t *testing.T, s string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("%v: %s", err, s)
	}
	return v
}

func TestAPIEndToEndAndContract(t *testing.T) {
	e := setup(t)
	alice, _ := e.user("alice")
	bob, bobEmail := e.user("bob")

	me := decodeJSON[meResp](t, alice.do("GET", "/me", nil, 200))
	if me.ViaToken || me.Email == "" {
		t.Fatalf("me %+v", me)
	}
	org := decodeJSON[orgResp](t, alice.do("POST", "/orgs", map[string]string{"name": "Acme Yazılım"}, 201))
	if org.Slug != "acme-yazilim" {
		t.Fatalf("slug %s", org.Slug)
	}
	alice.do("POST", "/orgs", map[string]string{"name": "Acme Yazılım"}, 422) // slug taken
	alice.do("PATCH", "/orgs/"+org.Slug, map[string]string{"name": "Acme"}, 200)
	alice.do("GET", "/orgs", nil, 200)

	p := decodeJSON[projectResp](t, alice.do("POST", "/orgs/"+org.Slug+"/projects",
		map[string]any{"repo_url": "git@github.com:acme/web-shop.git", "branches": []string{"main"}}, 201))
	if p.Slug != "web-shop" || p.Provider != "github" {
		t.Fatalf("project %+v", p)
	}
	alice.do("POST", "/orgs/"+org.Slug+"/projects", map[string]any{"repo_url": "file:///etc/passwd"}, 422)
	alice.do("GET", "/orgs/"+org.Slug+"/projects", nil, 200)
	alice.do("GET", "/orgs/"+org.Slug+"/projects/web-shop", nil, 200)
	alice.do("PATCH", "/orgs/"+org.Slug+"/projects/web-shop", map[string]any{"branches": []string{"main", "release"}}, 200)

	alice.do("POST", "/orgs/"+org.Slug+"/members", map[string]string{"email": bobEmail, "role": "viewer"}, 204)
	alice.do("GET", "/orgs/"+org.Slug+"/members", nil, 200)
	inv := decodeJSON[invitationResp](t, alice.do("POST", "/orgs/"+org.Slug+"/invitations", map[string]string{"email": "new@example.test", "role": "member"}, 201))
	if !strings.HasPrefix(inv.Token, "scanx_inv_") {
		t.Fatal("invitation token missing")
	}
	alice.do("GET", "/orgs/"+org.Slug+"/invitations", nil, 200)

	tok := decodeJSON[tokenResp](t, alice.do("POST", "/orgs/"+org.Slug+"/tokens", map[string]any{"name": "ci", "scopes": []string{"read"}}, 201))
	alice.do("GET", "/orgs/"+org.Slug+"/tokens", nil, 200)
	alice.do("GET", "/orgs/"+org.Slug+"/audit", nil, 200)

	// Read-only token: can read, cannot write, cannot see other orgs.
	ro := alice.withToken(tok.Token)
	if m := decodeJSON[meResp](t, ro.do("GET", "/me", nil, 200)); !m.ViaToken {
		t.Fatal("via_token expected")
	}
	ro.do("GET", "/orgs/"+org.Slug+"/projects", nil, 200)
	ro.do("POST", "/orgs/"+org.Slug+"/projects", map[string]any{"repo_url": "git@github.com:a/b.git"}, 403)
	alice.withToken("scanx_pat_"+strings.Repeat("Z", 40)).do("GET", "/me", nil, 401)

	// Viewer cannot write.
	bob.do("GET", "/orgs/"+org.Slug+"/projects/web-shop", nil, 200)
	bob.do("DELETE", "/orgs/"+org.Slug+"/projects/web-shop", nil, 403)
	bob.do("GET", "/orgs/"+org.Slug+"/audit", nil, 403)

	// Scans (Faz 3): deploy key, queue, read back, cancel; viewers cannot scan.
	alice.do("GET", "/orgs/"+org.Slug+"/projects/web-shop/deploy-key", nil, 200)
	sc := decodeJSON[struct {
		ID     uuid.UUID `json:"id"`
		Status string    `json:"status"`
	}](t, alice.do("POST", "/orgs/"+org.Slug+"/projects/web-shop/scans", map[string]any{"branch": "main"}, 202))
	if sc.Status != "queued" {
		t.Fatalf("scan %+v", sc)
	}
	alice.do("POST", "/orgs/"+org.Slug+"/projects/web-shop/scans", map[string]any{"branch": "-x"}, 422)
	alice.do("GET", "/orgs/"+org.Slug+"/projects/web-shop/scans", nil, 200)
	alice.do("GET", "/orgs/"+org.Slug+"/scans/"+sc.ID.String(), nil, 200)
	alice.do("GET", "/orgs/"+org.Slug+"/scans/"+sc.ID.String()+"/issues", nil, 200)
	alice.do("GET", "/orgs/"+org.Slug+"/scans/"+sc.ID.String()+"/reports/html", nil, 404)
	alice.do("GET", "/orgs/"+org.Slug+"/projects/web-shop/issues?status=open", nil, 200)
	bob.do("POST", "/orgs/"+org.Slug+"/projects/web-shop/scans", nil, 403)
	alice.do("POST", "/orgs/"+org.Slug+"/scans/"+sc.ID.String()+"/cancel", nil, 204)
	alice.do("POST", "/orgs/"+org.Slug+"/scans/"+sc.ID.String()+"/cancel", nil, 409)
	(&client{e: e, http: &http.Client{}}).do("POST", "/hooks/github/"+p.ID.String(), map[string]any{"ref": "refs/heads/main"}, 401)

	// Last owner cannot leave.
	alice.do("DELETE", "/orgs/"+org.Slug+"/members/"+me.ID.String(), nil, 409)

	// Unauthenticated.
	anon := &client{e: e, http: &http.Client{}}
	anon.do("GET", "/me", nil, 401)
	anon.do("GET", "/orgs/"+org.Slug, nil, 401)

	// Malformed bodies.
	alice.do("POST", "/orgs/"+org.Slug+"/projects", map[string]any{"repo_url": "git@github.com:a/b.git", "evil": true}, 400)

	alice.do("DELETE", "/orgs/"+org.Slug+"/tokens/"+tok.ID.String(), nil, 204)
	ro.do("GET", "/me", nil, 401)
	alice.do("DELETE", "/orgs/"+org.Slug+"/invitations/"+inv.ID.String(), nil, 204)
	alice.do("DELETE", "/orgs/"+org.Slug+"/projects/web-shop", nil, 204)
	alice.do("POST", "/auth/logout", nil, 204)
	alice.do("GET", "/me", nil, 401)
}

func TestCSRFRequiredForCookieRequests(t *testing.T) {
	e := setup(t)
	alice, _ := e.user("alice")
	req, _ := http.NewRequest("POST", e.ts.URL+"/api/v1/orgs", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := alice.http.Do(req) // session cookie, no CSRF token
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF token: status %d", resp.StatusCode)
	}
	req2, _ := http.NewRequest("POST", e.ts.URL+"/api/v1/orgs", strings.NewReader(`{"name":"x"}`))
	req2.Header.Set("Sec-Fetch-Site", "cross-site")
	req2.Header.Set("X-CSRF-Token", "forged")
	resp2, err := alice.http.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site request: status %d", resp2.StatusCode)
	}
}

// TestTenantIsolationAllEndpoints is the mandatory table-driven test (spec
// §5.4): a user of org A, authenticated by session and by a write token,
// tries every org-scoped endpoint against org B's resources → always 404.
func TestTenantIsolationAllEndpoints(t *testing.T) {
	e := setup(t)
	alice, _ := e.user("alice")
	bob, bobEmail := e.user("bob")
	_ = bobEmail
	orgA := decodeJSON[orgResp](t, alice.do("POST", "/orgs", map[string]string{"name": "Org A"}, 201))
	orgB := decodeJSON[orgResp](t, bob.do("POST", "/orgs", map[string]string{"name": "Org B"}, 201))
	bobMe := decodeJSON[meResp](t, bob.do("GET", "/me", nil, 200))
	bob.do("POST", "/orgs/"+orgB.Slug+"/projects", map[string]any{"repo_url": "git@github.com:b/secret-repo.git"}, 201)
	scanB := decodeJSON[struct {
		ID uuid.UUID `json:"id"`
	}](t, bob.do("POST", "/orgs/"+orgB.Slug+"/projects/secret-repo/scans", map[string]any{"branch": "main"}, 202))
	invB := decodeJSON[invitationResp](t, bob.do("POST", "/orgs/"+orgB.Slug+"/invitations", map[string]string{"email": "x@example.test", "role": "viewer"}, 201))
	tokB := decodeJSON[tokenResp](t, bob.do("POST", "/orgs/"+orgB.Slug+"/tokens", map[string]any{"name": "b"}, 201))
	tokA := decodeJSON[tokenResp](t, alice.do("POST", "/orgs/"+orgA.Slug+"/tokens", map[string]any{"name": "a", "scopes": []string{"write"}}, 201))

	b := "/orgs/" + orgB.Slug
	cases := []struct {
		method, path string
		body         any
	}{
		{"GET", b, nil},
		{"PATCH", b, map[string]string{"name": "pwned"}},
		{"GET", b + "/members", nil},
		{"POST", b + "/members", map[string]string{"email": "a@example.test", "role": "owner"}},
		{"PATCH", b + "/members/" + bobMe.ID.String(), map[string]string{"role": "viewer"}},
		{"DELETE", b + "/members/" + bobMe.ID.String(), nil},
		{"GET", b + "/invitations", nil},
		{"POST", b + "/invitations", map[string]string{"email": "a@example.test", "role": "owner"}},
		{"DELETE", b + "/invitations/" + invB.ID.String(), nil},
		{"GET", b + "/tokens", nil},
		{"POST", b + "/tokens", map[string]any{"name": "x"}},
		{"DELETE", b + "/tokens/" + tokB.ID.String(), nil},
		{"GET", b + "/audit", nil},
		{"GET", b + "/projects", nil},
		{"POST", b + "/projects", map[string]any{"repo_url": "git@github.com:a/b.git"}},
		{"GET", b + "/projects/secret-repo", nil},
		{"PATCH", b + "/projects/secret-repo", map[string]any{"name": "pwned"}},
		{"DELETE", b + "/projects/secret-repo", nil},
		{"GET", b + "/projects/secret-repo/deploy-key", nil},
		{"GET", b + "/projects/secret-repo/scans", nil},
		{"POST", b + "/projects/secret-repo/scans", map[string]any{"branch": "main"}},
		{"GET", b + "/projects/secret-repo/issues", nil},
		{"GET", b + "/scans/" + scanB.ID.String(), nil},
		{"GET", b + "/scans/" + scanB.ID.String() + "/issues", nil},
		{"POST", b + "/scans/" + scanB.ID.String() + "/cancel", nil},
		{"GET", b + "/scans/" + scanB.ID.String() + "/reports/html", nil},
		{"GET", "/orgs/" + orgA.Slug + "/scans/" + scanB.ID.String(), nil},
		{"POST", "/orgs/" + orgA.Slug + "/scans/" + scanB.ID.String() + "/cancel", nil},
		// Org A's own resource ids used under org B's slug must not leak either.
		{"DELETE", "/orgs/" + orgA.Slug + "/tokens/" + tokB.ID.String(), nil},
	}
	callers := map[string]*client{"session": alice, "token": alice.withToken(tokA.Token)}
	for name, c := range callers {
		for _, tc := range cases {
			want := 404
			if strings.HasPrefix(tc.path, "/orgs/"+orgA.Slug) {
				want = 404 // org A exists for alice, but the token id belongs to org B
			}
			t.Run(name+" "+tc.method+" "+tc.path, func(t *testing.T) {
				c.e.t = t
				c.do(tc.method, tc.path, tc.body, want)
			})
		}
	}
	// Bob's data is intact.
	bob.e.t = t
	bob.do("GET", b+"/projects/secret-repo", nil, 200)
	if o := decodeJSON[orgResp](t, bob.do("GET", b, nil, 200)); o.Name != "Org B" {
		t.Fatalf("org B modified: %+v", o)
	}
	bob.withToken(tokB.Token).do("GET", "/me", nil, 200)
}
