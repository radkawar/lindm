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
	"lindm/internal/device/assistance"
	"lindm/internal/device/core"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

// Console reads on the separate console pool are served while device traffic
// holds every device-pool connection, as composed by the server. They never
// acquire a device-pool connection, each finishes inside a deadline a starved
// read would exhaust, and their p95 stays within the admin-read budget, or on a
// host too loaded to meet it at all, within twice the same run's unsaturated
// p95. The same read on the saturated device pool cannot complete.
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
	const poolConns = 2
	devicePool, consolePool := poolOf(poolConns), poolOf(poolConns)
	now := time.Now().UTC()
	ca, caKey := testCA(t, now.Add(90*24*time.Hour))
	cfg := core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: caKey, Identity: localIdentity(t, consolePool)}
	runtime := assistance.NewRuntime()
	devices, err := New(devicePool, cfg, runtime)
	if err != nil {
		t.Fatal(err)
	}
	console, err := New(consolePool, cfg, runtime)
	if err != nil {
		t.Fatal(err)
	}
	owner := identity.WithPrincipal(ctx, insertPrincipal(t, ctx, conn, identity.RoleOwner))
	var held []*pgxpool.Conn
	saturate := func() {
		t.Helper()
		for len(held) < poolConns {
			deviceConn, err := devicePool.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			held = append(held, deviceConn)
		}
	}
	release := func() {
		for _, deviceConn := range held {
			deviceConn.Release()
		}
		held = held[:0]
	}
	t.Cleanup(release)
	saturate()
	saturated, cancel := context.WithTimeout(owner, 300*time.Millisecond)
	defer cancel()
	if _, err := devices.GetFleetSummary(saturated, connect.NewRequest(&adminv1.GetFleetSummaryRequest{})); err == nil {
		t.Fatal("device pool was not saturated; the regression would prove nothing")
	}
	// A console read that waited on the saturated device pool would block until
	// this deadline, far beyond the budget, and fail.
	const starvedRead = 5 * time.Second
	read := func() time.Duration {
		t.Helper()
		bounded, cancel := context.WithTimeout(owner, starvedRead)
		defer cancel()
		before := devicePool.Stat()
		started := time.Now()
		_, err := console.GetFleetSummary(bounded, connect.NewRequest(&adminv1.GetFleetSummaryRequest{}))
		elapsed := time.Since(started)
		if err != nil {
			t.Fatalf("console read failed after %v with %d of %d device-pool connections held: %v", elapsed, len(held), poolConns, err)
		}
		if after := devicePool.Stat(); after.AcquireCount() != before.AcquireCount() || after.CanceledAcquireCount() != before.CanceledAcquireCount() {
			t.Fatal("console read acquired a device-pool connection")
		}
		return elapsed
	}
	// Warm the console pool's connections and prepared statements first; the
	// budget applies to steady-state console reads, not connection setup.
	for range 3 {
		read()
	}
	// Saturated and unsaturated reads alternate, so both see the same host.
	var underSaturation, unsaturated []time.Duration
	for range 20 {
		saturate()
		underSaturation = append(underSaturation, read())
		release()
		unsaturated = append(unsaturated, read())
	}
	p95 := func(latencies []time.Duration) time.Duration {
		slices.Sort(latencies)
		return latencies[len(latencies)*95/100-1]
	}
	saturatedP95, unsaturatedP95 := p95(underSaturation), p95(unsaturated)
	t.Logf("console p95 %v under device saturation, %v unsaturated; samples %v and %v", saturatedP95, unsaturatedP95, underSaturation, unsaturated)
	// The 500 ms budget is the published admin-read p95. When this run's own
	// unsaturated reads already miss it (race-detector suites beside disk-heavy
	// lab lanes stretch every durable commit), the host cannot judge the budget;
	// device saturation must then still not slow console reads.
	if limit := max(500*time.Millisecond, 2*unsaturatedP95); saturatedP95 >= limit {
		t.Fatalf("console p95 %v under device saturation exceeds %v: the 500 ms admin-read budget, or twice this run's unsaturated p95 %v", saturatedP95, limit, unsaturatedP95)
	}
}
