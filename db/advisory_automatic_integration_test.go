// SPDX-License-Identifier: Apache-2.0

//go:build integration

package db_test

import (
	"strings"
	"testing"

	"lindm/db"
	"lindm/internal/testdb"
)

func TestAutomaticAdvisoryAuthorityRequiresFencedRestoreBelowFloor(t *testing.T) {
	pool, _ := testdb.Open(t)
	status, err := db.Preflight(t.Context(), pool)
	if err != nil || status.Floor < 58 {
		t.Fatalf("automatic source authority admitted older runtime: %+v %v", status, err)
	}
	provider := downProvider(t, pool, 58)
	var before string
	if err := pool.QueryRow(t.Context(), "SELECT row_to_json(c)::text FROM lindm_schema_compatibility c").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(t.Context(), 57); err == nil || !strings.Contains(err.Error(), "fenced") {
		t.Fatalf("automatic advisory Down did not require fenced restore: %v", err)
	}
	var after string
	if err := pool.QueryRow(t.Context(), "SELECT row_to_json(c)::text FROM lindm_schema_compatibility c").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("refused Down changed exact compatibility authority")
	}
}
