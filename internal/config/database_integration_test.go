// SPDX-License-Identifier: Apache-2.0
//go:build integration

package config

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"lindm/internal/testdb"
)

func TestDatabaseUTCStartupPreservesNinetyDayReleaseConstraintAcrossDST(t *testing.T) {
	pool, _ := testdb.Open(t)
	legacy, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Release()
	if _, err := legacy.Exec(t.Context(), "SET TIME ZONE 'America/New_York'"); err != nil {
		t.Fatal(err)
	}

	// October to January crosses the fall-back transition. A fresh release's
	// ninety-day Go duration must not become a ninety-day-plus-one-hour minimum.
	released := time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC)
	support := released.Add(30*time.Minute + 90*24*time.Hour)
	const insert = "INSERT INTO released_agent_series (major,minor,released_at,support_until,minimum_protocol,maximum_protocol) VALUES (0,$1,$2,$3,1,1)"
	_, err = legacy.Exec(t.Context(), insert, 2, released, support)
	var refusal *pgconn.PgError
	if !errors.As(err, &refusal) || refusal.Code != "23514" {
		t.Fatalf("non-UTC baseline did not reproduce the release check refusal: %v", err)
	}

	dir := databaseFixture(t)
	writeFixtureFile(t, dir, "database-url", []byte("postgresql://user:fixture-secret@db1/database?sslmode=verify-full"))
	configured, err := (&Document{base: dir}).database("database-url")
	if err != nil {
		t.Fatal(err)
	}
	// Keep the real disposable database's protected transport and credentials;
	// exercise the startup parameters produced by the actual config parser.
	startup := pool.Config()
	for name, value := range configured.ConnConfig.RuntimeParams {
		startup.ConnConfig.RuntimeParams[name] = value
	}
	application, err := pgxpool.NewWithConfig(t.Context(), startup)
	if err != nil {
		t.Fatal(err)
	}
	defer application.Close()
	var zone string
	if err := application.QueryRow(t.Context(), "SHOW timezone").Scan(&zone); err != nil || zone != "UTC" {
		t.Fatalf("application connection did not start in UTC: %q, %v", zone, err)
	}
	if _, err := application.Exec(t.Context(), insert, 2, released, support); err != nil {
		t.Fatalf("UTC startup did not admit the unchanged ninety-day release: %v", err)
	}
	_, err = application.Exec(t.Context(), insert, 3, released, released.Add(90*24*time.Hour-time.Second))
	if !errors.As(err, &refusal) || refusal.Code != "23514" {
		t.Fatalf("UTC startup weakened the minimum ninety-day constraint: %v", err)
	}
}
