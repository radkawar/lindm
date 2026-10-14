// SPDX-License-Identifier: Apache-2.0

//go:build integration

package devlab

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"lindm/internal/config"
)

func TestDropInvalidDatabasesSparesValidOnes(t *testing.T) {
	_, repository := nativeServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	document, err := config.Load(filepath.Join(FixturePath(repository), "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := authorityDatabaseAdmin(document, FixturePath(repository))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.ConnectConfig(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	name := func() string { return "lindm_authority_" + strings.ReplaceAll(uuid.NewString(), "-", "") }
	invalid, valid := name(), name()
	for _, database := range []string{invalid, valid} {
		if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()+" TEMPLATE template0"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "DROP DATABASE IF EXISTS "+pgx.Identifier{valid}.Sanitize())
	})
	// The mark PostgreSQL itself leaves when a drop is interrupted.
	if _, err := conn.Exec(ctx, "UPDATE pg_database SET datconnlimit = -2 WHERE datname = $1", invalid); err != nil {
		t.Fatal(err)
	}
	listed, err := dropInvalid(ctx, conn, true)
	if err != nil || !slices.Contains(listed, invalid) || slices.Contains(listed, valid) {
		t.Fatalf("dry run listed %v: %v", listed, err)
	}
	dropped, err := dropInvalid(ctx, conn, false)
	if err != nil || !slices.Contains(dropped, invalid) || slices.Contains(dropped, valid) {
		t.Fatalf("dropped %v: %v", dropped, err)
	}
	var present []string
	rows, err := conn.Query(ctx, "SELECT datname FROM pg_database WHERE datname = ANY($1)", []string{invalid, valid})
	if err != nil {
		t.Fatal(err)
	}
	if present, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || !slices.Equal(present, []string{valid}) {
		t.Fatalf("remaining %v: %v", present, err)
	}
}
