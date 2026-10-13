//go:build integration

package testdb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/internal/agent/nativeexec"
	"lindm/internal/custody"
	"lindm/internal/labexec"
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
	defer clear(dsn)
	var database *Database
	if container := os.Getenv("LINDM_TEST_DATABASE_TEMPLATE_CONTAINER"); container != "" {
		template, templateErr := migratedTemplate()
		if templateErr != nil {
			t.Fatal(templateErr)
		}
		database, err = NewFromTemplate(t.Context(), strings.TrimSpace(string(dsn)), template)
	} else {
		database, err = New(t.Context(), strings.TrimSpace(string(dsn)))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("database fixture: create=%s initialize=%s check=%s connect=%s", database.timings.create, database.timings.initialize, database.timings.check, database.timings.connect)
	t.Cleanup(func() {
		started := time.Now()
		if err := database.Close(); err != nil {
			t.Error(err)
		}
		t.Logf("database fixture: cleanup=%s", time.Since(started))
	})
	return database.Pool, database.Conn
}

// One integration binary uses one run-owned database fixture. Cache only its
// immutable migration snapshot; never application connections or mutable rows.
// The code under test (not the checkout launching devenv) runs its migrations.
var migratedTemplate = sync.OnceValues(func() (_ Template, resultErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	path := os.Getenv("LINDM_TEST_DATABASE_URL_FILE")
	if _, err := custody.Owned(path, false); err != nil {
		return Template{}, err
	}
	dsn, err := os.ReadFile(path)
	if err != nil {
		return Template{}, err
	}
	defer clear(dsn)
	started := time.Now()
	golden, err := New(ctx, strings.TrimSpace(string(dsn)))
	if err != nil {
		return Template{}, err
	}
	migrated := time.Now()
	defer func() { resultErr = errors.Join(resultErr, golden.Close()) }()
	output := nativeexec.NewBuffer(8 << 20)
	container := os.Getenv("LINDM_TEST_DATABASE_TEMPLATE_CONTAINER")
	if err := labexec.Run(ctx, labexec.Command{
		Path: "docker", Args: []string{"exec", "--user", "postgres", container, "pg_dump", "--username=postgres", "--dbname=" + golden.config.Database, "--schema=" + golden.Schema(), "--no-owner", "--no-privileges", "--inserts"},
		Stdout: output, Stderr: os.Stderr, Timeout: 2 * time.Minute,
	}); err != nil {
		return Template{}, fmt.Errorf("snapshot integration migrations: %w", err)
	}
	if output.Truncated() {
		return Template{}, errors.New("integration migration snapshot exceeds 8 MiB")
	}
	var sql strings.Builder
	for line := range strings.SplitSeq(output.String(), "\n") {
		// pg_dump 18 wraps plain SQL in psql's client-only restriction guards.
		// --inserts avoids COPY client commands; everything remaining is SQL.
		if strings.HasPrefix(line, "\\restrict ") || strings.HasPrefix(line, "\\unrestrict ") {
			continue
		}
		if strings.HasPrefix(line, "\\") {
			return Template{}, errors.New("unexpected client command in integration migration snapshot")
		}
		sql.WriteString(line)
		sql.WriteByte('\n')
	}
	fmt.Printf("integration migration template: migrate=%s snapshot=%s bytes=%d\n", migrated.Sub(started), time.Since(migrated), sql.Len())
	return Template{Schema: golden.Schema(), SQL: sql.String()}, nil
})
