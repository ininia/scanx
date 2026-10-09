//go:build integration

package store

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ininia/scanx/internal/secret"
)

// testDSNs returns the admin (schema owner) and app (RLS-bound) URLs.
// scripts/dev.sh test-integration and CI always provide both.
func testDSNs(t *testing.T) (admin, app secret.Secret) {
	t.Helper()
	a, b := os.Getenv("SCANX_TEST_DATABASE_ADMIN_URL"), os.Getenv("SCANX_TEST_DATABASE_URL")
	if a == "" || b == "" {
		t.Skip("SCANX_TEST_DATABASE_ADMIN_URL / SCANX_TEST_DATABASE_URL not set; run via scripts/dev.sh test-integration")
	}
	return secret.Secret(a), secret.Secret(b)
}

func migrated(t *testing.T) (ctx context.Context, admin, app *pgxpool.Pool) {
	t.Helper()
	adminDSN, appDSN := testDSNs(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := Migrate(ctx, adminDSN, log); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var err error
	if admin, err = Open(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	if app, err = Open(ctx, appDSN); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	return ctx, admin, app
}

func TestMigrateIsIdempotentAndCurrent(t *testing.T) {
	ctx, _, app := migrated(t)
	adminDSN, _ := testDSNs(t)
	if err := Migrate(ctx, adminDSN, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := MigrationsCurrent(ctx, app); err != nil {
		t.Fatalf("app role cannot verify migrations: %v", err)
	}
}

func TestOpenRejectsBadURLWithoutLeaking(t *testing.T) {
	_, err := Open(context.Background(), secret.Secret("postgres://u:FAKEleak@%zz"))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "FAKEleak") {
		t.Fatalf("error leaks password: %v", err)
	}
}

func TestAppRoleIsNotPrivileged(t *testing.T) {
	ctx, _, app := migrated(t)
	var super, bypass bool
	err := app.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super, &bypass)
	if err != nil {
		t.Fatal(err)
	}
	if super || bypass {
		t.Fatalf("app role must not be superuser (%v) or BYPASSRLS (%v)", super, bypass)
	}
	if _, err := app.Exec(ctx, `CREATE TABLE should_fail (id int)`); err == nil {
		t.Fatal("app role must not be able to run DDL")
	}
}

// TestRLSIsolatesOrganizations is the first instance of the mandatory tenant
// isolation test (spec §5.4): org A context must never see org B rows.
func TestRLSIsolatesOrganizations(t *testing.T) {
	ctx, admin, app := migrated(t)

	var orgA, orgB, userA, userB string
	seed := `
WITH a AS (INSERT INTO organizations (name, slug) VALUES ('Org A', 'rls-a-' || substr(gen_random_uuid()::text, 1, 8)) RETURNING id),
     b AS (INSERT INTO organizations (name, slug) VALUES ('Org B', 'rls-b-' || substr(gen_random_uuid()::text, 1, 8)) RETURNING id),
     ua AS (INSERT INTO users (email, password_hash) VALUES ('a-' || gen_random_uuid()::text || '@example.test', 'x') RETURNING id),
     ub AS (INSERT INTO users (email, password_hash) VALUES ('b-' || gen_random_uuid()::text || '@example.test', 'x') RETURNING id)
SELECT a.id, b.id, ua.id, ub.id FROM a, b, ua, ub`
	if err := admin.QueryRow(ctx, seed).Scan(&orgA, &orgB, &userA, &userB); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx,
		`INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, 'owner'), ($3, $4, 'owner')`,
		orgA, userA, orgB, userB); err != nil {
		t.Fatal(err)
	}

	inTenant := func(org, user string, fn func(pgx.Tx)) {
		t.Helper()
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx,
			`SELECT set_config('scanx.org_id', $1, true), set_config('scanx.user_id', $2, true)`,
			org, user); err != nil {
			t.Fatal(err)
		}
		fn(tx)
	}
	count := func(tx pgx.Tx, q string, args ...any) int {
		t.Helper()
		var n int
		if err := tx.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	inTenant(orgA, userA, func(tx pgx.Tx) {
		if n := count(tx, `SELECT count(*) FROM organizations WHERE id = $1`, orgB); n != 0 {
			t.Errorf("org A sees org B organization row")
		}
		if n := count(tx, `SELECT count(*) FROM memberships WHERE org_id = $1`, orgB); n != 0 {
			t.Errorf("org A sees org B memberships")
		}
		if n := count(tx, `SELECT count(*) FROM organizations WHERE id = $1`, orgA); n != 1 {
			t.Errorf("org A cannot see itself")
		}
		// Writing into another tenant must be rejected by WITH CHECK.
		_, err := tx.Exec(ctx, `INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, 'viewer')`, orgB, userA)
		if err == nil {
			t.Errorf("org A could insert a membership into org B")
		}
	})

	inTenant(orgA, userA, func(tx pgx.Tx) {
		tag, err := tx.Exec(ctx, `UPDATE organizations SET name = 'pwned' WHERE id = $1`, orgB)
		if err != nil {
			t.Fatal(err)
		}
		if tag.RowsAffected() != 0 {
			t.Errorf("org A updated org B")
		}
	})

	// No tenant context at all: nothing is visible.
	inTenant("", "", func(tx pgx.Tx) {
		if n := count(tx, `SELECT count(*) FROM organizations WHERE id IN ($1, $2)`, orgA, orgB); n != 0 {
			t.Errorf("rows visible without tenant context: %d", n)
		}
	})
}
