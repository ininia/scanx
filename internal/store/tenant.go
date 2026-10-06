package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ininia/scanx/internal/store/db"
)

// Scope is the tenant context a transaction runs under. Row-level security
// policies read it through scanx_current_org(), scanx_current_user() and
// scanx_is_superadmin().
type Scope struct {
	OrgID      uuid.UUID
	UserID     uuid.UUID
	Superadmin bool
}

// ErrNotFound is returned when a row does not exist or is invisible to the
// current tenant (both look the same on purpose: spec §5.4 → 404).
var ErrNotFound = errors.New("not found")

// DB runs tenant-scoped transactions.
type DB struct {
	Pool *pgxpool.Pool
}

// Tx runs fn in a transaction whose tenant settings are LOCAL to it, so they
// can never leak to another request through the connection pool.
func (d *DB) Tx(ctx context.Context, sc Scope, fn func(q *db.Queries) error) error {
	tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	org, user, super := "", "", ""
	if sc.OrgID != uuid.Nil {
		org = sc.OrgID.String()
	}
	if sc.UserID != uuid.Nil {
		user = sc.UserID.String()
	}
	if sc.Superadmin {
		super = "on"
	}
	if _, err := tx.Exec(ctx,
		`SELECT set_config('scanx.org_id', $1, true), set_config('scanx.user_id', $2, true), set_config('scanx.superadmin', $3, true)`,
		org, user, super); err != nil {
		return fmt.Errorf("store: tenant context: %w", err)
	}
	if err := fn(db.New(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// NotFound maps pgx.ErrNoRows to ErrNotFound.
func NotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
