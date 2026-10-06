package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/ininia/scanx/internal/secret"
)

func TestRedactsSensitiveKeys(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(&buf, "debug", "json")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("login",
		"password", "FAKE-pw",
		"Authorization", "Bearer FAKE-tok",
		"api_token", 12345,
		"session_cookie", "FAKE-cookie",
		"database_url", "postgres://u:FAKE@h/db",
		slog.Group("req", slog.String("private_key", "FAKE-pk")),
		"secret_value", secret.Secret("FAKE-s"),
		"user", "alice",
	)
	out := buf.String()
	if strings.Contains(out, "FAKE") || strings.Contains(out, "12345") {
		t.Fatalf("secret leaked: %s", out)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["user"] != "alice" {
		t.Fatalf("non-sensitive field lost: %v", m)
	}
	if m["password"] != redacted {
		t.Fatalf("password = %v", m["password"])
	}
}

func TestSecretTypeRedactedUnderNeutralKey(t *testing.T) {
	var buf bytes.Buffer
	log, _ := New(&buf, "info", "text")
	log.Info("x", "value", secret.Secret("FAKE-neutral"))
	if strings.Contains(buf.String(), "FAKE-neutral") {
		t.Fatalf("secret leaked: %s", buf.String())
	}
}

func TestContextAttrs(t *testing.T) {
	var buf bytes.Buffer
	log, _ := New(&buf, "info", "json")
	ctx := WithAttrs(context.Background(), slog.String("request_id", "r1"))
	ctx = WithAttrs(ctx, slog.String("org_id", "o1"))
	log.InfoContext(ctx, "hello")
	out := buf.String()
	if !strings.Contains(out, `"request_id":"r1"`) || !strings.Contains(out, `"org_id":"o1"`) {
		t.Fatalf("context attrs missing: %s", out)
	}
	buf.Reset()
	log.With("component", "http").InfoContext(ctx, "again")
	if !strings.Contains(buf.String(), `"component":"http"`) || !strings.Contains(buf.String(), "r1") {
		t.Fatalf("With lost attrs: %s", buf.String())
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log, _ := New(&buf, "warn", "json")
	log.Info("hidden")
	if buf.Len() != 0 {
		t.Fatal("info should be filtered at warn level")
	}
	log.Warn("shown")
	if buf.Len() == 0 {
		t.Fatal("warn should be logged")
	}
}

func TestInvalidOptions(t *testing.T) {
	if _, err := New(&bytes.Buffer{}, "loud", "json"); err == nil {
		t.Fatal("expected level error")
	}
	if _, err := New(&bytes.Buffer{}, "info", "xml"); err == nil {
		t.Fatal("expected format error")
	}
}

func TestIsSensitiveKey(t *testing.T) {
	for _, k := range []string{"PASSWORD", "x_token", "master_key", "Cookie", "privateKey"} {
		if !IsSensitiveKey(k) {
			t.Errorf("%q should be sensitive", k)
		}
	}
	for _, k := range []string{"user", "scan_id", "status", "path"} {
		if IsSensitiveKey(k) {
			t.Errorf("%q should not be sensitive", k)
		}
	}
}
