//go:build integration

package testdb

import (
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/internal/custody"
)

// Open preserves the integration-test API and registers independent cleanup.
// LINDM_TEST_DATABASE_URL_FILE names an owner-only file holding the DSN, so
// the password never appears in argv or the environment.
func Open(t *testing.T) (*pgxpool.Pool, *pgx.Conn) {
	t.Helper()
	path := os.Getenv("LINDM_TEST_DATABASE_URL_FILE")
	if path == "" {
		t.Fatal("integration tests require LINDM_TEST_DATABASE_URL_FILE; use go run ./cmd/devenv test-integration")
	}
	if _, err := custody.Owned(path, false); err != nil {
		t.Fatalf("LINDM_TEST_DATABASE_URL_FILE: %v", err)
	}
	dsn, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	database, err := New(t.Context(), strings.TrimSpace(string(dsn)))
	clear(dsn)
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
