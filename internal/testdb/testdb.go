// Package testdb creates throw-away PostgreSQL databases for integration
// tests that need a pristine instance (e.g. the first-run setup wizard).
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ininia/scanx/internal/secret"
)

// Fresh creates an empty database, returns admin and app URLs for it and
// drops it when the test ends. It skips the test when the integration
// environment is not configured.
func Fresh(t *testing.T) (admin, app secret.Secret) {
	t.Helper()
	adminURL, appURL := os.Getenv("SCANX_TEST_DATABASE_ADMIN_URL"), os.Getenv("SCANX_TEST_DATABASE_URL")
	if adminURL == "" || appURL == "" {
		t.Skip("SCANX_TEST_DATABASE_* not set; run via scripts/dev.sh test-integration")
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "scanx_t_" + hex.EncodeToString(b)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	ident := pgx.Identifier{name}.Sanitize()
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+ident); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "GRANT CONNECT ON DATABASE "+ident+" TO scanx_app"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(ctx, adminURL)
		if err != nil {
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)")
	})
	return secret.Secret(withDB(t, adminURL, name)), secret.Secret(withDB(t, appURL, name))
}

func withDB(t *testing.T, raw, name string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}
