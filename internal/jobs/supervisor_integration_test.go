// SPDX-License-Identifier: Apache-2.0

//go:build integration

package jobs

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"lindm/internal/testdb"
)

// instance is one simulated lindmd process: a supervisor plus its job ledger.
type instance struct {
	name    string
	cancel  context.CancelFunc
	done    chan struct{}
	starts  atomic.Int64
	running atomic.Bool
}

type ledger struct {
	mu      sync.Mutex
	active  int
	maximum int
}

func (l *ledger) enter() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active++
	l.maximum = max(l.maximum, l.active)
}

func (l *ledger) leave() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
}

func (l *ledger) peak() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.maximum
}

func randomKey() int64 { return rand.Int64N(1<<62) + 1 }

func startInstance(t *testing.T, connection *pgx.ConnConfig, name string, cfg Config, run func(context.Context, *instance) error) *instance {
	t.Helper()
	in := &instance{name: name, done: make(chan struct{})}
	cfg.Connection = connection
	for i := range cfg.Jobs {
		cfg.Jobs[i].Run = func(ctx context.Context) error { return run(ctx, in) }
	}
	supervisor, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	in.cancel = cancel
	go func() {
		defer close(in.done)
		supervisor.Run(ctx)
	}()
	t.Cleanup(in.stop)
	return in
}

func (in *instance) stop() {
	in.cancel()
	<-in.done
}

func fastConfig(job Job) Config {
	return Config{Jobs: []Job{job}, AcquireInterval: 50 * time.Millisecond, HeartbeatInterval: 50 * time.Millisecond, MinimumBackoff: 20 * time.Millisecond, MaximumBackoff: 200 * time.Millisecond}
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// holder returns the backend PID currently granted the advisory key.
func holder(t *testing.T, conn *pgx.Conn, key int64) int32 {
	t.Helper()
	var pid int32
	err := conn.QueryRow(t.Context(), "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND objsubid = 1 AND granted AND ((classid::bigint << 32) | objid::bigint) = $1", key).Scan(&pid)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

func leading(instances ...*instance) []*instance {
	var result []*instance
	for _, in := range instances {
		if in.running.Load() {
			result = append(result, in)
		}
	}
	return result
}

func TestExclusiveJobHasOneLeaderAndFailsOverOnSessionLoss(t *testing.T) {
	pool, conn := testdb.Open(t)
	key := randomKey()
	var jobs ledger
	run := func(ctx context.Context, in *instance) error {
		jobs.enter()
		in.starts.Add(1)
		in.running.Store(true)
		<-ctx.Done()
		in.running.Store(false)
		jobs.leave()
		return ctx.Err()
	}
	a := startInstance(t, pool.Config().ConnConfig, "a", fastConfig(Job{Name: "exclusive", Key: key, Mode: Exclusive}), run)
	b := startInstance(t, pool.Config().ConnConfig, "b", fastConfig(Job{Name: "exclusive", Key: key, Mode: Exclusive}), run)
	waitFor(t, "a leader", func() bool { return len(leading(a, b)) == 1 })
	// Both peers poll many times; neither may start a second copy.
	time.Sleep(500 * time.Millisecond)
	if jobs.peak() != 1 || a.starts.Load()+b.starts.Load() != 1 {
		t.Fatalf("steady state ran %d concurrent copies after %d starts", jobs.peak(), a.starts.Load()+b.starts.Load())
	}
	pid := holder(t, conn, key)
	if pid == 0 {
		t.Fatal("running job has no granted advisory lock")
	}
	var terminated bool
	if err := conn.QueryRow(t.Context(), "SELECT pg_terminate_backend($1)", pid).Scan(&terminated); err != nil || !terminated {
		t.Fatalf("terminate coordination session: %v", err)
	}
	// The former leader notices within one heartbeat and stops its copy, and a
	// leader is re-established on a fresh session.
	waitFor(t, "a new leader after session loss", func() bool {
		next := holder(t, conn, key)
		return next != 0 && next != pid && len(leading(a, b)) == 1 && a.starts.Load()+b.starts.Load() == 2
	})
}

func TestExclusiveJobShutdownHandsOverPromptly(t *testing.T) {
	pool, _ := testdb.Open(t)
	key := randomKey()
	run := func(ctx context.Context, in *instance) error {
		in.starts.Add(1)
		in.running.Store(true)
		<-ctx.Done()
		in.running.Store(false)
		return nil
	}
	cfg := fastConfig(Job{Name: "exclusive", Key: key, Mode: Exclusive})
	a := startInstance(t, pool.Config().ConnConfig, "a", cfg, run)
	waitFor(t, "a leads", func() bool { return a.running.Load() })
	b := startInstance(t, pool.Config().ConnConfig, "b", fastConfig(Job{Name: "exclusive", Key: key, Mode: Exclusive}), run)
	time.Sleep(200 * time.Millisecond)
	if b.starts.Load() != 0 {
		t.Fatal("standby instance ran an exclusive job while the leader held it")
	}
	a.stop()
	if a.running.Load() {
		t.Fatal("stopped supervisor did not join its job")
	}
	// Explicit unlock lets the peer take over at its next acquisition poll.
	started := time.Now()
	waitFor(t, "b takes over", func() bool { return b.running.Load() })
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("handover took %s", elapsed)
	}
}

func TestExclusiveJobFailureReleasesLeadershipToPeer(t *testing.T) {
	pool, _ := testdb.Open(t)
	key := randomKey()
	run := func(ctx context.Context, in *instance) error {
		in.starts.Add(1)
		if in.name == "failing" {
			return errors.New("store unavailable")
		}
		in.running.Store(true)
		<-ctx.Done()
		in.running.Store(false)
		return nil
	}
	failingConfig := fastConfig(Job{Name: "exclusive", Key: key, Mode: Exclusive})
	failingConfig.MinimumBackoff, failingConfig.MaximumBackoff = time.Hour, time.Hour
	failing := startInstance(t, pool.Config().ConnConfig, "failing", failingConfig, run)
	waitFor(t, "failing instance attempts the job", func() bool { return failing.starts.Load() == 1 })
	healthy := startInstance(t, pool.Config().ConnConfig, "healthy", fastConfig(Job{Name: "exclusive", Key: key, Mode: Exclusive}), run)
	waitFor(t, "peer takes over after release", func() bool { return healthy.running.Load() })
	if failing.starts.Load() != 1 {
		t.Fatal("failed job was retried before its backoff")
	}
}

func TestReplicatedJobRestartsWithoutStoppingSupervisor(t *testing.T) {
	pool, _ := testdb.Open(t)
	var attempts atomic.Int64
	running := make(chan struct{})
	cfg := fastConfig(Job{Name: "replicated", Mode: Replicated})
	startInstance(t, pool.Config().ConnConfig, "a", cfg, func(ctx context.Context, _ *instance) error {
		if attempts.Add(1) < 3 {
			return errors.New("store unavailable")
		}
		close(running)
		<-ctx.Done()
		return nil
	})
	select {
	case <-running:
	case <-time.After(15 * time.Second):
		t.Fatal("replicated job was not restarted after failures")
	}
}
