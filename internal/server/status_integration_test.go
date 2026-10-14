// SPDX-License-Identifier: Apache-2.0

//go:build integration

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/testdb"
)

func TestOperationalHTTPSeparatesLivenessReadinessAndEvidence(t *testing.T) {
	pool, _ := testdb.Open(t)
	adminPool, err := pgxpool.NewWithConfig(t.Context(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adminPool.Close)
	status, err := newStatusMonitor(nil, "", false, func(context.Context, time.Time) []*adminv1.ServerStatusCheck { return nil }, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerOperationalHandlers(mux, pool, adminPool, status)
	request := func(method, path string, want int, body string) {
		t.Helper()
		response := httptest.NewRecorder()
		guard(mux).ServeHTTP(response, httptest.NewRequest(method, path, nil))
		if response.Code != want || (body != "" && !strings.Contains(response.Body.String(), body)) {
			t.Fatalf("%s %s: %d %q", method, path, response.Code, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("operational response was cacheable")
		}
	}
	request("GET", "/readyz", http.StatusNoContent, "")
	request("GET", "/healthz", http.StatusNoContent, "")
	request("GET", "/metrics", http.StatusOK, `lindm_server_status_state{component="backups"} 1`)
	request("POST", "/metrics", http.StatusMethodNotAllowed, "")
	adminPool.Close()
	request("GET", "/readyz", http.StatusServiceUnavailable, "not ready\n")
	request("GET", "/healthz", http.StatusNoContent, "")
	pool.Close()
	request("GET", "/readyz", http.StatusServiceUnavailable, "not ready\n")
	request("GET", "/healthz", http.StatusNoContent, "")
}
