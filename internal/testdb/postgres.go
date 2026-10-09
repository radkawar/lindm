// Package testdb isolates PostgreSQL integration cases in disposable schemas.
// Tests use the application's migration runner, not a second SQL-file parser.
package testdb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/db"
)

// Database owns one disposable schema, its pool and an independent test
// connection. All application connections have a schema-only search_path.
type Database struct {
	Pool *pgxpool.Pool
	Conn *pgx.Conn

	schema  string
	config  *pgx.ConnConfig
	created bool
	once    sync.Once
	err     error
}

// New creates a private schema and applies the application's real migrations.
// The supplied role needs CREATE SCHEMA, not superuser or CREATE DATABASE.
// Close must be called even when the caller's context has been cancelled.
func New(ctx context.Context, dsn string) (_ *Database, resultErr error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid integration database connection configuration")
	}
	database := &Database{
		schema: "lindm_test_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		config: cfg.ConnConfig.Copy(),
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, database.Close())
		}
	}()
	admin, err := pgx.ConnectConfig(ctx, database.config.Copy())
	if err != nil {
		return nil, errors.New("connect isolated schema administration failed")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, admin.Close(cleanup))
	}()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{database.schema}.Sanitize()); err != nil {
		return nil, fmt.Errorf("create isolated schema %s: %w", database.schema, err)
	}
	database.created = true
	cfg.ConnConfig.RuntimeParams["search_path"] = database.schema
	cfg.MaxConns = 4
	database.Pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("create isolated schema pool failed")
	}
	if err := db.Migrate(ctx, database.Pool); err != nil {
		return nil, err
	}
	if err := db.Check(ctx, database.Pool); err != nil {
		return nil, err
	}
	database.Conn, err = pgx.ConnectConfig(ctx, cfg.ConnConfig.Copy())
	if err != nil {
		return nil, errors.New("connect isolated test connection failed")
	}
	return database, nil
}

// Schema returns the exact owned name for bounded cleanup diagnostics.
func (d *Database) Schema() string { return d.schema }

// Close releases connections before dropping only the owned schema. Cleanup
// reconnects independently, so an aborted test connection cannot prevent it.
// Each network cleanup has its own bounded, uncancelled context.
func (d *Database) Close() error {
	d.once.Do(func() {
		if d.Conn != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			d.err = errors.Join(d.err, d.Conn.Close(ctx))
			cancel()
		}
		if d.Pool != nil {
			d.Pool.Close()
		}
		if !d.created {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		admin, err := pgx.ConnectConfig(ctx, d.config.Copy())
		if err != nil {
			d.err = errors.Join(d.err, fmt.Errorf("cleanup isolated schema %s: administration connection failed", d.schema))
			return
		}
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{d.schema}.Sanitize()+" CASCADE"); err != nil {
			d.err = errors.Join(d.err, fmt.Errorf("remove isolated schema %s: %w", d.schema, err))
		}
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		d.err = errors.Join(d.err, admin.Close(closeCtx))
	})
	return d.err
}
