// SPDX-License-Identifier: Apache-2.0

//go:build integration

package db_test

import (
	"strings"
	"testing"

	"lindm/db"
	"lindm/internal/testdb"
)

func TestAdvisoryAuthorityRequiresFencedRestoreBelowFloor(t *testing.T) {
	for _, migration := range []struct {
		name    string
		version int64
	}{
		{"automatic-sources", 58},
		{"vendor-race-refetches", 61},
	} {
		t.Run(migration.name, func(t *testing.T) {
			pool, _ := testdb.Open(t)
			status, err := db.Preflight(t.Context(), pool)
			if err != nil || status.Floor < migration.version {
				t.Fatalf("advisory authority admitted older runtime: %+v %v", status, err)
			}
			provider := downProvider(t, pool, migration.version)
			var before string
			if err := pool.QueryRow(t.Context(), "SELECT row_to_json(c)::text FROM lindm_schema_compatibility c").Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err := provider.DownTo(t.Context(), migration.version-1); err == nil || !strings.Contains(err.Error(), "fenced") {
				t.Fatalf("advisory Down did not require fenced restore: %v", err)
			}
			var after string
			if err := pool.QueryRow(t.Context(), "SELECT row_to_json(c)::text FROM lindm_schema_compatibility c").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatal("refused Down changed exact compatibility authority")
			}
		})
	}
}
