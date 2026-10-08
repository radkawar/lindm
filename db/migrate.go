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
	"github.com/pressly/goose/v3/database"
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

// Check requires exactly the embedded applied migration set, not merely a matching
// maximum version. It detects gaps and newer schemas without executing any DDL.
func Check(ctx context.Context, pool *pgxpool.Pool) (err error) {
	db := stdlib.OpenDBFromPool(pool)
	defer func() { err = errors.Join(err, db.Close()) }()
	sources, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, sources)
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	store, err := database.NewStore(database.DialectPostgres, "goose_db_version")
	if err != nil {
		return err
	}
	rows, err := store.ListMigrations(ctx, db)
	if err != nil {
		return fmt.Errorf("read schema versions; run the explicit migration command first: %w", err)
	}
	// The store returns history in descending insertion order. Only the newest
	// record for a version describes its current applied/reverted state.
	applied := make(map[int64]bool, len(rows))
	for _, row := range rows {
		if _, seen := applied[row.Version]; !seen {
			applied[row.Version] = row.IsApplied
		}
	}
	delete(applied, 0)
	for _, source := range provider.ListSources() {
		if !applied[source.Version] {
			return fmt.Errorf("schema migration %d is missing; run the explicit migration command", source.Version)
		}
		delete(applied, source.Version)
	}
	for version, present := range applied {
		if present {
			return fmt.Errorf("schema migration %d is newer than this binary supports", version)
		}
	}
	return nil
}
