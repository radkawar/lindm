// SPDX-License-Identifier: Apache-2.0

// Package db owns embedded schema migrations and read-only startup compatibility
// checks. Serving traffic never applies migrations or creates version tables.
package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrate applies pending migrations under PostgreSQL's session advisory lock.
// Callers supply a pool authenticated with the explicit migration credential.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (err error) {
	db := stdlib.OpenDBFromPool(pool)
	defer func() { err = errors.Join(err, db.Close()) }()
	sources, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, sources, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("initialize migrations: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

// Check requires every embedded migration and an exact, migration-owner-written
// compatibility record before accepting a newer schema. Serving never runs DDL.
func Check(ctx context.Context, pool *pgxpool.Pool) error {
	status, err := Preflight(ctx, pool)
	if err != nil {
		return err
	}
	if len(status.Pending) > 0 {
		return fmt.Errorf("schema migration %d is missing; run the explicit migration command", status.Pending[0])
	}
	if !status.Compatible {
		return fmt.Errorf("schema migration %d is newer than this binary supports (minimum runtime schema %d)", status.Current, status.Floor)
	}
	return nil
}
