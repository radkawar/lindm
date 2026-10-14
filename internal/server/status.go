// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/agent/buildinfo"
	"lindm/internal/jobs"
	"lindm/internal/server/serverdb"
)

const statusCadence = time.Minute

var statusComponents = [...]string{"database", "admin_database", "https_certificate", "console_ca", "device_https_certificate", "device_ca", "backups", "server_release_feed", "agent_repository", "advisory_feeds", "disk", "job_queue"}

type statusProbe func(context.Context, time.Time) []*adminv1.ServerStatusCheck

// statusMonitor publishes immutable, redacted observations. Requests never run
// probes or launch workers. Original evidence times survive every refresh.
type statusMonitor struct {
	pool       *pgxpool.Pool
	instance   string
	alerts     bool
	probe      statusProbe
	clock      func() time.Time
	latest     atomic.Pointer[adminv1.GetServerStatusResponse]
	supervisor *jobs.Supervisor
}

func newStatusMonitor(pool *pgxpool.Pool, instance string, alerts bool, probe statusProbe, clock func() time.Time) (*statusMonitor, error) {
	if probe == nil || clock == nil || (alerts && (pool == nil || instance == "")) {
		return nil, errors.New("server status: probe, clock and configured notification resources required")
	}
	m := &statusMonitor{pool: pool, instance: instance, alerts: alerts, probe: probe, clock: clock}
	checks := make([]*adminv1.ServerStatusCheck, 0, len(statusComponents))
	for _, component := range statusComponents {
		checks = append(checks, statusCheck(component, adminv1.ServerStatusState_SERVER_STATUS_STATE_UNKNOWN, "No check has completed yet.", "Wait for the next server check.", time.Time{}))
	}
	m.latest.Store(&adminv1.GetServerStatusResponse{Version: buildinfo.Current().Version, Checks: checks})
	return m, nil
}

func statusCheck(component string, state adminv1.ServerStatusState, summary, action string, now time.Time) *adminv1.ServerStatusCheck {
	check := &adminv1.ServerStatusCheck{Component: component, State: state, Summary: summary, NextAction: action}
	if !now.IsZero() {
		check.ObservedAt = timestamppb.New(now)
	}
	return check
}

func (m *statusMonitor) snapshot() *adminv1.GetServerStatusResponse {
	response := proto.CloneOf(m.latest.Load())
	if response.ObservedAt != nil && m.clock().Sub(response.ObservedAt.AsTime()) > 2*statusCadence {
		for _, check := range response.Checks {
			check.State = adminv1.ServerStatusState_SERVER_STATUS_STATE_UNKNOWN
			check.Summary = "The server check has not refreshed."
			check.NextAction = "Inspect the server service journal."
		}
	}
	return response
}

func (m *statusMonitor) collect(ctx context.Context) {
	now := m.clock()
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	checks := m.probe(probeCtx, now)
	cancel()
	if m.supervisor != nil {
		workers := m.supervisor.Health()
		for _, check := range checks {
			if check.Component != "job_queue" {
				continue
			}
			check.Detail += fmt.Sprintf("; %d local loops running, %d waiting for leadership or startup, %d stopped unexpectedly", workers.Running, workers.Waiting, workers.Failed)
			if workers.Failed > 0 {
				check.State = adminv1.ServerStatusState_SERVER_STATUS_STATE_FAILED
				check.Summary = "A local background worker stopped unexpectedly."
				check.NextAction = "Inspect the server service journal while the supervisor retries."
			}
		}
	}
	m.latest.Store(&adminv1.GetServerStatusResponse{Version: buildinfo.Current().Version, ObservedAt: timestamppb.New(now), Checks: checks})
	if !m.alerts {
		return
	}
	for _, check := range checks {
		notifyCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := serverdb.New(m.pool).RecordServerStatusTransition(notifyCtx, serverdb.RecordServerStatusTransitionParams{Instance: m.instance, Component: check.Component, State: int32(check.State), EvidenceKey: statusEvidenceKey(check)})
		cancel()
		if err != nil {
			// Never log dependency error strings; they may include credentials.
			slog.Warn("server status notification unavailable", "component", check.Component)
		}
	}
}

// A distinct authenticated release notice needs an alert even while an older
// notice already needs attention. Polling timestamps never form its identity.
func statusEvidenceKey(check *adminv1.ServerStatusCheck) string {
	if check.Component != "server_release_feed" {
		return ""
	}
	digest := sha256.Sum256([]byte(check.Detail))
	return hex.EncodeToString(digest[:])
}

func (m *statusMonitor) run(ctx context.Context) error {
	m.collect(ctx)
	ticker := time.NewTicker(statusCadence)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			m.collect(ctx)
		}
	}
}

// metrics exposes only a closed set of numeric health gauges. No hostnames,
// certificate subjects, database URLs, package versions or error text are labels.
func (m *statusMonitor) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	response := m.latest.Load()
	stale := response.ObservedAt != nil && m.clock().Sub(response.ObservedAt.AsTime()) > 2*statusCadence
	if _, err := fmt.Fprint(w, "# HELP lindm_server_status_state Component state: 1 unknown, 2 confirmed, 3 attention, 4 failed, 5 inactive.\n# TYPE lindm_server_status_state gauge\n# HELP lindm_server_status_observed_seconds Last component check time in Unix seconds.\n# TYPE lindm_server_status_observed_seconds gauge\n# HELP lindm_server_status_evidence_seconds Original component evidence time in Unix seconds.\n# TYPE lindm_server_status_evidence_seconds gauge\n# HELP lindm_server_status_expiry_seconds Component evidence expiry in Unix seconds.\n# TYPE lindm_server_status_expiry_seconds gauge\n"); err != nil {
		return
	}
	for _, check := range response.Checks {
		observed, evidence, expiry := int64(0), int64(0), int64(0)
		if check.ObservedAt != nil {
			observed = check.ObservedAt.AsTime().Unix()
		}
		if check.EvidenceAt != nil {
			evidence = check.EvidenceAt.AsTime().Unix()
		}
		if check.ExpiresAt != nil {
			expiry = check.ExpiresAt.AsTime().Unix()
		}
		state := check.State
		if stale {
			state = adminv1.ServerStatusState_SERVER_STATUS_STATE_UNKNOWN
		}
		if _, err := fmt.Fprintf(w, "lindm_server_status_state{component=%q} %d\nlindm_server_status_observed_seconds{component=%q} %d\nlindm_server_status_evidence_seconds{component=%q} %d\nlindm_server_status_expiry_seconds{component=%q} %d\n", check.Component, state, check.Component, observed, check.Component, evidence, check.Component, expiry); err != nil {
			return
		}
	}
}

func registerOperationalHandlers(mux *http.ServeMux, pool, adminPool *pgxpool.Pool, status *statusMonitor) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		probe, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(probe); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		if err := adminPool.Ping(probe); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /metrics", status.metrics)
}
