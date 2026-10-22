package tlscheck

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func rules(r *Result) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range r.Findings {
		m[f.RuleID] = f
	}
	return m
}

func TestCheckAgainstTLSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "x"})
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	r := Check(context.Background(), host, p, Options{AllowPrivate: true, Roots: roots, Timeout: 3 * time.Second})
	if r.Error != "" || r.Cert == nil || !r.Cert.Trusted {
		t.Fatalf("%+v", r)
	}
	if !r.Protocols["TLS 1.3"] || r.Protocols["TLS 1.0"] || r.HTTPStatus != 200 {
		t.Fatalf("protocols %v status %d", r.Protocols, r.HTTPStatus)
	}
	got := rules(r)
	for _, id := range []string{"TLS012", "TLS014", "TLS015", "TLS016", "TLS017", "TLS018", "TLS021"} {
		if _, ok := got[id]; !ok {
			t.Errorf("missing %s in %+v", id, r.Findings)
		}
	}
	for _, id := range []string{"TLS001", "TLS003", "TLS004", "TLS007", "TLS009"} {
		if _, ok := got[id]; ok {
			t.Errorf("unexpected %s", id)
		}
	}
	if r.Grade == "" || r.Score >= 100 {
		t.Fatalf("score %d %s", r.Score, r.Grade)
	}

	// Without the test CA the chain is untrusted; close to expiry is flagged.
	r = Check(context.Background(), host, p, Options{AllowPrivate: true, Timeout: 3 * time.Second, Now: srv.Certificate().NotAfter.Add(-5 * 24 * time.Hour)})
	got = rules(r)
	if _, ok := got["TLS004"]; !ok {
		t.Errorf("untrusted chain not reported: %+v", r.Findings)
	}
	if f, ok := got["TLS002"]; !ok || f.Severity != "critical" {
		t.Errorf("expiry: %+v", r.Findings)
	}
}

func TestPrivateTargetsBlocked(t *testing.T) {
	r := Check(context.Background(), "127.0.0.1", 443, Options{Timeout: time.Second})
	if r.Error == "" || r.Grade != "F" {
		t.Fatalf("%+v", r)
	}
}

func TestHSTSMaxAge(t *testing.T) {
	if hstsMaxAge("max-age=31536000; includeSubDomains") != 31536000 || hstsMaxAge(`max-age="300"`) != 300 || hstsMaxAge("preload") != 0 {
		t.Fatal("hsts")
	}
}
