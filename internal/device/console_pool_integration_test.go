//go:build integration

package device

import (
	"context"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/core"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

// Console reads on the separate console pool stay within the admin-read budget
// while device traffic holds every device-pool connection, as composed by the
// server. The same read on the saturated device pool cannot complete.
func TestConsolePoolServesAdminReadsUnderDeviceSaturation(t *testing.T) {
	ctx := t.Context()
	base, conn := testdb.Open(t)
	poolOf := func(conns int32) *pgxpool.Pool {
		t.Helper()
		cfg := base.Config().Copy()
		cfg.MaxConns = conns
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	devicePool, consolePool := poolOf(2), poolOf(2)
	now := time.Now().UTC()
	ca, caKey := testCA(t, now.Add(90*24*time.Hour))
	cfg := core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, consolePool)}
	devices, err := New(devicePool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	console, err := New(consolePool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	owner := identity.WithPrincipal(ctx, insertPrincipal(t, ctx, conn, identity.RoleOwner))
	for range 2 {
		held, err := devicePool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(held.Release)
	}
	saturated, cancel := context.WithTimeout(owner, 300*time.Millisecond)
	defer cancel()
	if _, err := devices.GetFleetSummary(saturated, connect.NewRequest(&adminv1.GetFleetSummaryRequest{})); err == nil {
		t.Fatal("device pool was not saturated; the regression would prove nothing")
	}
	// Warm the console pool's connections and prepared statements first; the
	// budget applies to steady-state console reads, not connection setup.
	for range 3 {
		if _, err := console.GetFleetSummary(owner, connect.NewRequest(&adminv1.GetFleetSummaryRequest{})); err != nil {
			t.Fatalf("console warm-up under device saturation: %v", err)
		}
	}
	var latencies []time.Duration
	for range 20 {
		started := time.Now()
		if _, err := console.GetFleetSummary(owner, connect.NewRequest(&adminv1.GetFleetSummaryRequest{})); err != nil {
			t.Fatalf("console read under device saturation: %v", err)
		}
		latencies = append(latencies, time.Since(started))
	}
	slices.Sort(latencies)
	if p95 := latencies[len(latencies)*95/100-1]; p95 >= 500*time.Millisecond {
		t.Fatalf("console p95 %v under device saturation exceeds the 500 ms admin-read budget", p95)
	}
}
