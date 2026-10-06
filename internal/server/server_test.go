package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func do(t *testing.T, h http.Handler, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestLive(t *testing.T) {
	for _, p := range []string{"/health/live", "/api/v1/health/live"} {
		rec := do(t, New(Options{}), http.MethodGet, p, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", p, rec.Code)
		}
		var body healthResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Status != "ok" {
			t.Fatalf("%s: body %s err %v", p, rec.Body, err)
		}
	}
}

func TestReady(t *testing.T) {
	ok := Check{Name: "db", Fn: func(context.Context) error { return nil }}
	bad := Check{Name: "migrations", Fn: func(context.Context) error {
		return errors.New("pq: password authentication failed for user FAKE")
	}}

	rec := do(t, New(Options{ReadyChecks: []Check{ok}}), http.MethodGet, "/health/ready", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("ready status %d", rec.Code)
	}

	rec = do(t, New(Options{ReadyChecks: []Check{ok, bad}}), http.MethodGet, "/health/ready", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status %d", rec.Code)
	}
	var body healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "fail" || body.Checks["db"] != "ok" || body.Checks["migrations"] != "fail" {
		t.Fatalf("unexpected body %+v", body)
	}
	if strings.Contains(rec.Body.String(), "password") {
		t.Fatalf("internal error leaked: %s", rec.Body)
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := do(t, New(Options{}), http.MethodGet, "/health/live", nil)
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("weak CSP %q", csp)
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must be off without https")
	}
	rec = do(t, New(Options{HSTS: true}), http.MethodGet, "/health/live", nil)
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS missing with https")
	}
}

func TestRequestID(t *testing.T) {
	rec := do(t, New(Options{}), http.MethodGet, "/health/live", map[string]string{HeaderRequestID: "abcdef12-3456"})
	if got := rec.Header().Get(HeaderRequestID); got != "abcdef12-3456" {
		t.Fatalf("valid incoming id not kept: %q", got)
	}
	for _, evil := range []string{"<script>", "short", strings.Repeat("a", 65), "a b c d e f g h"} {
		rec = do(t, New(Options{}), http.MethodGet, "/health/live", map[string]string{HeaderRequestID: evil})
		got := rec.Header().Get(HeaderRequestID)
		if got == evil || !validRequestID.MatchString(got) {
			t.Fatalf("invalid incoming id %q was not replaced (got %q)", evil, got)
		}
	}
}

func TestNotFoundJSON(t *testing.T) {
	for _, p := range []string{"/nope", "/api/v1/nope"} {
		rec := do(t, New(Options{}), http.MethodGet, p, nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", p, rec.Code)
		}
		var body ErrorBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Error.Code != "not_found" || body.Error.RequestID == "" {
			t.Fatalf("bad error body %+v", body)
		}
	}
	rec := do(t, New(Options{}), http.MethodPost, "/health/live", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST live: %d", rec.Code)
	}
}

func TestRecoverHidesPanicDetails(t *testing.T) {
	r := chi.NewRouter()
	r.Use(RequestID, Recover)
	r.Get("/boom", func(http.ResponseWriter, *http.Request) { panic("FAKE internal detail") })
	rec := do(t, r, http.MethodGet, "/boom", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "FAKE") {
		t.Fatalf("panic detail leaked: %s", rec.Body)
	}
}

func TestStatusRecorderDefaults(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	if _, err := rec.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	rec.WriteHeader(http.StatusTeapot) // ignored after first write
	if rec.status != http.StatusOK || rec.bytes != 2 {
		t.Fatalf("status=%d bytes=%d", rec.status, rec.bytes)
	}
}
