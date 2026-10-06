package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ininia/scanx/internal/config"
)

func parseEnv(t *testing.T, s string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("bad line %q", line)
		}
		m[k] = v
	}
	return m
}

func TestGenerateSecretsValidAndUnique(t *testing.T) {
	var a, b bytes.Buffer
	if err := GenerateSecrets(&a); err != nil {
		t.Fatal(err)
	}
	if err := GenerateSecrets(&b); err != nil {
		t.Fatal(err)
	}
	ea, eb := parseEnv(t, a.String()), parseEnv(t, b.String())
	for _, k := range []string{"POSTGRES_PASSWORD", "SCANX_APP_DB_PASSWORD", "SCANX_MASTER_KEY", "SCANX_SESSION_KEY", "SCANX_SETUP_TOKEN"} {
		if ea[k] == "" {
			t.Fatalf("%s missing", k)
		}
		if ea[k] == eb[k] {
			t.Fatalf("%s not random", k)
		}
	}
	key, err := base64.StdEncoding.DecodeString(ea["SCANX_MASTER_KEY"])
	if err != nil || len(key) != 32 {
		t.Fatalf("master key invalid: %v len=%d", err, len(key))
	}
	// Generated values must pass config validation.
	cfg, err := config.LoadFrom(map[string]string{
		"SCANX_MASTER_KEY":  ea["SCANX_MASTER_KEY"],
		"SCANX_SESSION_KEY": ea["SCANX_SESSION_KEY"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(config.NeedKeys); err != nil {
		t.Fatalf("generated keys rejected: %v", err)
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateSelfSignedCert(dir, []string{"scanx.local", "127.0.0.1"}, false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("scanx.local"); err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(dir, "key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("key mode %v", st.Mode().Perm())
		}
	}

	// ifMissing keeps the existing pair.
	if err := GenerateSelfSignedCert(dir, []string{"other"}, true); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if !bytes.Equal(raw, again) {
		t.Fatal("ifMissing overwrote existing cert")
	}
	if err := GenerateSelfSignedCert(t.TempDir(), nil, false); err == nil {
		t.Fatal("expected error without hosts")
	}
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	if err := Healthcheck(context.Background(), ok.URL); err != nil {
		t.Fatal(err)
	}
	if err := Healthcheck(context.Background(), bad.URL); err == nil {
		t.Fatal("expected failure on 503")
	}
	if err := Healthcheck(context.Background(), "http://127.0.0.1:1/nope"); err == nil {
		t.Fatal("expected connection failure")
	}
}
