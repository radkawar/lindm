// SPDX-License-Identifier: Apache-2.0

//go:build integration

package server

import (
	"errors"
	"net/http"
	"testing"

	"lindm/internal/config"
	"lindm/internal/serverops"
	"lindm/internal/testdb"
)

func TestRunRejectsRestoreHoldBeforeInitializingServices(t *testing.T) {
	pool, _ := testdb.Open(t)
	result, err := pool.Exec(t.Context(), "UPDATE server_recovery_state SET hold = true WHERE singleton")
	if err != nil {
		t.Fatal(err)
	}
	if result.RowsAffected() != 1 {
		t.Fatal("recovery state does not contain exactly one deployment row")
	}
	// Only the pool and HTTP client are supplied deliberately. A restore hold
	// must reject direct Run callers before authentication, key loading,
	// listener binding or background workers can begin.
	resources := &config.Resources{
		Database:      pool.Config(),
		AdminDatabase: pool.Config(),
		HTTPClient:    &http.Client{},
	}
	if err := Run(t.Context(), resources); !errors.Is(err, serverops.ErrRestoreHold) {
		t.Fatalf("restore-held Run returned %v; want ErrRestoreHold before service initialization", err)
	}
}
