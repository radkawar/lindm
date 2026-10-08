//go:build integration

package testdb

import (
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Open preserves the integration-test API and registers independent cleanup.
func Open(t *testing.T) (*pgxpool.Pool, *pgx.Conn) {
	t.Helper()
	dsn := os.Getenv("LINDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("integration tests require LINDM_TEST_DATABASE_URL; use make test-integration")
	}
	database, err := New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Error(err)
		}
	})
	return database.Pool, database.Conn
}
