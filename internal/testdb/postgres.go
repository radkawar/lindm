//go:build integration

// Package testdb isolates PostgreSQL integration cases in disposable schemas.
// Tests use the application's migration runner, not a second SQL-file parser.
package testdb

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/db"
)

// Open creates a private schema for this test, applies the real migrations and
// removes only that schema during cleanup. The supplied role needs CREATE SCHEMA,
// not superuser or CREATE DATABASE privileges. Never modify the public schema.
func Open(t *testing.T) (*pgxpool.Pool, *pgx.Conn) {
	t.Helper()
	dsn := os.Getenv("LINDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("integration tests require LINDM_TEST_DATABASE_URL; use make test-integration")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid integration database connection configuration")
	}
	ctx := t.Context()
	admin, err := pgx.ConnectConfig(ctx, cfg.ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	schema := "lindm_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	created := false
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if created {
			if _, err := admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
				t.Errorf("remove isolated schema: %v", err)
			}
		}
		if err := admin.Close(cleanup); err != nil {
			t.Errorf("close schema administration connection: %v", err)
		}
	})
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	created = true
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.ConnectConfig(ctx, cfg.ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := conn.Close(cleanup); err != nil {
			t.Errorf("close test connection: %v", err)
		}
	})
	return pool, conn
}
