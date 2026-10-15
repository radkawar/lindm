// SPDX-License-Identifier: Apache-2.0

//go:build integration

package db_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"lindm/db"
	"lindm/internal/testdb"
)

// Arrange predecessor history without executing a security Down migration.
// Business tables remain intact so the actual repository Down runs against DDL.
func downProvider(t *testing.T, pool *pgxpool.Pool, version int64) *goose.Provider {
	t.Helper()
	if _, err := pool.Exec(t.Context(), "DELETE FROM goose_db_version WHERE version_id > $1", version); err != nil {
		t.Fatal(err)
	}
	floor := int64(51)
	if version < floor {
		floor = 49
	}
	if _, err := pool.Exec(t.Context(), `UPDATE lindm_schema_compatibility SET minimum_runtime_version=$1, migration_versions=(SELECT array_agg(version_id ORDER BY version_id) FROM goose_db_version WHERE version_id > 0 AND is_applied)`, floor); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	sources := fstest.MapFS{}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), fmt.Sprintf("%05d_", version)) {
			content, err := os.ReadFile("migrations/" + entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			sources[entry.Name()] = &fstest.MapFile{Data: content}
		}
	}
	if len(sources) != 1 {
		t.Fatalf("migration %d: found %d sources", version, len(sources))
	}
	sqlDB := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Error(err)
		}
	})
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, sources)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestAssistanceSecurityDownRefusesBeforeMutation(t *testing.T) {
	for _, version := range []int64{55, 56} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			pool, _ := testdb.Open(t)
			provider := downProvider(t, pool, version)
			var before string
			if err := pool.QueryRow(t.Context(), "SELECT row_to_json(c)::text FROM lindm_schema_compatibility c").Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err := provider.DownTo(t.Context(), version-1); err == nil || !strings.Contains(err.Error(), "fenced") {
				t.Fatalf("security Down did not require fenced restore: %v", err)
			}
			var after string
			if err := pool.QueryRow(t.Context(), "SELECT row_to_json(c)::text FROM lindm_schema_compatibility c").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatal("refused Down changed compatibility evidence")
			}
			for _, table := range []string{"assistance_recordings", "assistance_recording_segments", "assistance_recording_retrievals", "assistance_recording_deletions", "assistance_reconnect_workflows", "assistance_unattended_grants", "assistance_unattended_enrollments"} {
				var exists bool
				if err := pool.QueryRow(t.Context(), "SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists); err != nil || !exists {
					t.Fatalf("refused Down lost %s: %v", table, err)
				}
			}
			if _, err := db.Preflight(t.Context(), pool); err != nil {
				t.Fatalf("refused Down changed exact history: %v", err)
			}
		})
	}
}

func TestReversiblePolicyDownUpdatesExactCompatibilityHistory(t *testing.T) {
	for _, version := range []int64{50, 54, 57} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			pool, _ := testdb.Open(t)
			provider := downProvider(t, pool, version)
			if _, err := provider.DownTo(t.Context(), version-1); err != nil {
				t.Fatal(err)
			}
			status, err := db.Preflight(t.Context(), pool)
			if err != nil {
				t.Fatalf("successful Down left stale policy: %v", err)
			}
			if status.Current != version-1 {
				t.Fatalf("Down history = %+v", status)
			}
		})
	}
}

func TestReversiblePolicyDownNeverLowersContractFloor(t *testing.T) {
	for _, version := range []int64{50, 54, 57} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			pool, _ := testdb.Open(t)
			provider := downProvider(t, pool, version)
			if _, err := pool.Exec(t.Context(), "UPDATE lindm_schema_compatibility SET minimum_runtime_version=$1", version); err != nil {
				t.Fatal(err)
			}
			if _, err := provider.DownTo(t.Context(), version-1); err == nil {
				t.Fatal("Down weakened the retained contract floor")
			}
			var floor int64
			if err := pool.QueryRow(t.Context(), "SELECT minimum_runtime_version FROM lindm_schema_compatibility").Scan(&floor); err != nil || floor != version {
				t.Fatalf("contract floor=%d err=%v", floor, err)
			}
		})
	}
}

func TestRPMAuthoritySecurityDownRefusesBeforeMutation(t *testing.T) {
	pool, _ := testdb.Open(t)
	provider := downProvider(t, pool, 59)
	if _, err := pool.Exec(t.Context(), "UPDATE lindm_schema_compatibility SET minimum_runtime_version=59"); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := pool.QueryRow(t.Context(), "SELECT row_to_json(c)::text FROM lindm_schema_compatibility c").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(t.Context(), 58); err == nil || !strings.Contains(err.Error(), "fenced") {
		t.Fatalf("RPM authority Down did not require fenced restore: %v", err)
	}
	var after string
	if err := pool.QueryRow(t.Context(), "SELECT row_to_json(c)::text FROM lindm_schema_compatibility c").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("refused RPM authority Down changed compatibility evidence")
	}
	fields := []string{"rpm_authority", "rpm_signer", "rpm_authority_reason", "source_architecture"}
	var retained int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='snapshot_packages' AND column_name=ANY($1::text[])", fields).Scan(&retained); err != nil || retained != len(fields) {
		t.Fatalf("refused Down lost authority columns: retained=%d err=%v", retained, err)
	}
	var projection bool
	if err := pool.QueryRow(t.Context(), "SELECT to_regclass('advisory_set_uncovered') IS NOT NULL").Scan(&projection); err != nil || !projection {
		t.Fatalf("refused Down lost durable uncovered projection: %v", err)
	}
	if _, err := db.Preflight(t.Context(), pool); err != nil {
		t.Fatalf("refused RPM authority Down changed exact history: %v", err)
	}
}
