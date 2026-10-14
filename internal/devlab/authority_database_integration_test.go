// SPDX-License-Identifier: Apache-2.0

//go:build integration

package devlab

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The drop's lock budget bounds only lock waits. An admitted DROP DATABASE forces
// and waits for an immediate cluster-wide checkpoint, which takes far longer than
// ten milliseconds on the shared cluster, so this drop succeeds only if that
// storage work is not cancelled at the lock budget. A single three-minute bound
// on the whole drop failed teardown whenever a checkpoint outlasted it. Blocked
// drops are covered by TestPersistentDestroyReportsRemainingSessions.
func TestOwnedDatabaseDropLockBudgetSparesCheckpointWork(t *testing.T) {
	_, repository := nativeServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	material, err := ReadPublicAgentFixture(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	shared := FixturePath(repository)
	document, err := authorityDocument(ctx, filepath.Join(t.TempDir(), "server.json"), shared, material)
	if err != nil {
		t.Fatal(err)
	}
	database, err := newAuthorityDatabase(ctx, document, shared)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			t.Error(err)
		}
	}()
	const lockBudget = 10 * time.Millisecond
	started := time.Now()
	// The caller deadline is the test's: only the lock budget is short.
	if err := database.drop(t.Context(), false, lockBudget); err != nil {
		t.Fatalf("admitted drop cancelled by the %s lock budget: %v", lockBudget, err)
	}
	elapsed := time.Since(started)
	connection, err := pgx.ConnectConfig(t.Context(), database.admin.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := connection.Close(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	}()
	var present bool
	if err := connection.QueryRow(t.Context(), "SELECT EXISTS (SELECT FROM pg_database WHERE datname=$1)", database.name).Scan(&present); err != nil || present {
		t.Fatalf("drop retained owned database %s: present=%t err=%v", database.name, present, err)
	}
	t.Logf("owned database %s dropped in %s with a %s lock budget", database.name, elapsed.Round(time.Millisecond), lockBudget)
}
