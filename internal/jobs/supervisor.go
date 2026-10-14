// SPDX-License-Identifier: Apache-2.0

// Package jobs supervises the control plane's background jobs across replicated
// lindmd instances. Exclusive jobs run on at most one instance at a time under a
// PostgreSQL session advisory lock held by a dedicated coordination session;
// replicated jobs run on every instance and fence their own durable row leases.
//
// Leadership is an exclusivity and efficiency boundary, not the sole correctness
// fence: a lost coordination session is detected within one heartbeat, so a
// former leader may overlap its successor for a bounded interval. Every job must
// therefore keep its writes transactional, row-locked and idempotent. Job
// failures never terminate the process; they release leadership and retry with
// jittered backoff, so a database failover cannot take down serving instances.
// The package owns no job semantics, schedules or SQL beyond the advisory lock.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Mode selects how a job is distributed across instances.
type Mode uint8

const (
	// Exclusive jobs run only while this instance holds the job's advisory lock.
	Exclusive Mode = iota + 1
	// Replicated jobs run on every instance and coordinate through row leases.
	Replicated
)

func (m Mode) String() string {
	switch m {
	case Exclusive:
		return "exclusive"
	case Replicated:
		return "replicated"
	default:
		return "invalid"
	}
}

// Job is one supervised background loop. Run must return promptly after its
// context is cancelled. A nil return without cancellation is an unexpected exit
// and is restarted like an error.
type Job struct {
	Name string
	// Key is the deployment-wide advisory lock key of an Exclusive job. Keys are
	// a compatibility contract between concurrently running releases.
	Key  int64
	Mode Mode
	Run  func(context.Context) error
}

// Config holds the supervisor's dependencies. Connection must be a dedicated
// copy of the runtime database configuration; the session is never pooled.
type Config struct {
	Connection *pgx.ConnConfig
	Jobs       []Job
	// Zero values select the production defaults below.
	AcquireInterval   time.Duration
	HeartbeatInterval time.Duration
	MinimumBackoff    time.Duration
	MaximumBackoff    time.Duration
}

const (
	defaultAcquireInterval   = 5 * time.Second
	defaultHeartbeatInterval = 2 * time.Second
	defaultMinimumBackoff    = time.Second
	defaultMaximumBackoff    = time.Minute
	operationTimeout         = 5 * time.Second
	connectTimeout           = 10 * time.Second
	maxJobs                  = 32
)

// Supervisor runs the configured jobs until its Run context is cancelled.
type Supervisor struct {
	connection *pgx.ConnConfig
	exclusive  []*exclusiveJob
	replicated []Job
	acquire    time.Duration
	heartbeat  time.Duration
	minBackoff time.Duration
	maxBackoff time.Duration
}

type exclusiveJob struct {
	Job
	cancel   context.CancelFunc
	running  bool
	started  time.Time
	failures int
	retryAt  time.Time
}

type exit struct {
	job *exclusiveJob
	err error
}

// New validates every job before any goroutine or database session starts.
func New(cfg Config) (*Supervisor, error) {
	if cfg.Connection == nil || len(cfg.Jobs) == 0 || len(cfg.Jobs) > maxJobs {
		return nil, errors.New("jobs: connection and between 1 and 32 jobs are required")
	}
	s := &Supervisor{
		connection: cfg.Connection.Copy(),
		acquire:    valueOr(cfg.AcquireInterval, defaultAcquireInterval),
		heartbeat:  valueOr(cfg.HeartbeatInterval, defaultHeartbeatInterval),
		minBackoff: valueOr(cfg.MinimumBackoff, defaultMinimumBackoff),
		maxBackoff: valueOr(cfg.MaximumBackoff, defaultMaximumBackoff),
	}
	if s.acquire < 0 || s.heartbeat < 0 || s.minBackoff < 0 || s.maxBackoff < s.minBackoff {
		return nil, errors.New("jobs: intervals must be positive and backoff bounds ordered")
	}
	names := make(map[string]bool, len(cfg.Jobs))
	keys := make(map[int64]bool, len(cfg.Jobs))
	for _, job := range cfg.Jobs {
		if job.Name == "" || len(job.Name) > 64 || names[job.Name] || job.Run == nil {
			return nil, fmt.Errorf("jobs: job %q needs a unique bounded name and a run function", job.Name)
		}
		names[job.Name] = true
		switch job.Mode {
		case Exclusive:
			if job.Key == 0 || keys[job.Key] {
				return nil, fmt.Errorf("jobs: exclusive job %q needs a unique nonzero advisory key", job.Name)
			}
			keys[job.Key] = true
			s.exclusive = append(s.exclusive, &exclusiveJob{Job: job})
		case Replicated:
			if job.Key != 0 {
				return nil, fmt.Errorf("jobs: replicated job %q must not claim an advisory key", job.Name)
			}
			s.replicated = append(s.replicated, job)
		default:
			return nil, fmt.Errorf("jobs: job %q has no valid mode", job.Name)
		}
	}
	// Name the coordination session so operators can map lock holders to
	// instances through pg_locks and pg_stat_activity.
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	if s.connection.RuntimeParams == nil {
		s.connection.RuntimeParams = make(map[string]string)
	}
	name := fmt.Sprintf("lindmd jobs %s pid %d", host, os.Getpid())
	if len(name) > 63 {
		name = name[:63]
	}
	s.connection.RuntimeParams["application_name"] = name
	return s, nil
}

func valueOr(value, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return value
}

// Run joins every job before returning. Exclusive leadership is released
// explicitly on cancellation so a peer can take over without waiting for the
// database to notice the closed session.
func (s *Supervisor) Run(ctx context.Context) {
	var group sync.WaitGroup
	for _, job := range s.replicated {
		group.Go(func() { s.runReplicated(ctx, job) })
	}
	if len(s.exclusive) > 0 {
		group.Go(func() { s.coordinate(ctx) })
	}
	group.Wait()
}

func (s *Supervisor) runReplicated(ctx context.Context, job Job) {
	failures := 0
	for {
		started := time.Now()
		slog.Info("background job started", "job", job.Name, "mode", Replicated.String())
		err := job.Run(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) >= s.maxBackoff {
			failures = 0
		}
		failures++
		delay := backoff(s.minBackoff, s.maxBackoff, failures)
		slog.Error("background job stopped; restarting", "job", job.Name, "mode", Replicated.String(), "err", describe(err), "retry_in", delay)
		if !sleep(ctx, delay) {
			return
		}
	}
}

// coordinator exclusively owns the coordination session; job goroutines never
// touch it. Session loss cancels and joins every led job before reconnecting.
type coordinator struct {
	*Supervisor
	conn     *pgx.Conn
	exits    chan exit
	group    sync.WaitGroup
	failures int
}

func (s *Supervisor) coordinate(ctx context.Context) {
	c := &coordinator{Supervisor: s, exits: make(chan exit, len(s.exclusive))}
	defer c.release(ctx, "shutdown")
	acquire := time.NewTimer(0)
	defer acquire.Stop()
	heartbeat := time.NewTicker(s.heartbeat)
	defer heartbeat.Stop()
	for {
		var err error
		select {
		case <-ctx.Done():
			return
		case finished := <-c.exits:
			err = c.finish(ctx, finished)
		case <-heartbeat.C:
			err = c.check(ctx)
		case <-acquire.C:
			if err = c.acquire(ctx); err == nil {
				resetTimer(acquire, jitter(s.acquire))
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.failures++
			delay := backoff(s.minBackoff, s.maxBackoff, c.failures)
			slog.Error("job coordination session unavailable", "err", err, "retry_in", delay)
			c.release(ctx, "session_lost")
			resetTimer(acquire, delay)
		}
	}
}

// acquire (re)connects to a writable primary and tries every idle job's lock.
func (c *coordinator) acquire(ctx context.Context) error {
	if c.conn == nil {
		connecting, cancel := context.WithTimeout(ctx, connectTimeout)
		defer cancel()
		conn, err := pgx.ConnectConfig(connecting, c.connection.Copy())
		if err != nil {
			return fmt.Errorf("connect: %w", err)
		}
		c.conn = conn
		// Advisory locks are per server: leadership taken on a hot standby would
		// not exclude a leader on the primary.
		var recovering bool
		if err := conn.QueryRow(connecting, "SELECT pg_is_in_recovery()").Scan(&recovering); err != nil {
			return fmt.Errorf("check primary: %w", err)
		}
		if recovering {
			return errors.New("jobs: coordination session reached a standby; use target_session_attrs=read-write")
		}
	}
	now := time.Now()
	for _, job := range c.exclusive {
		if job.running || now.Before(job.retryAt) {
			continue
		}
		trying, cancel := context.WithTimeout(ctx, operationTimeout)
		var acquired bool
		err := c.conn.QueryRow(trying, "SELECT pg_try_advisory_lock($1)", job.Key).Scan(&acquired)
		cancel()
		if err != nil {
			return fmt.Errorf("try advisory lock: %w", err)
		}
		if !acquired {
			continue
		}
		jobCtx, stop := context.WithCancel(ctx)
		job.cancel, job.running, job.started = stop, true, now
		slog.Info("background job leadership acquired", "job", job.Name, "mode", Exclusive.String())
		c.group.Go(func() { c.exits <- exit{job: job, err: job.Run(jobCtx)} })
	}
	c.failures = 0
	return nil
}

// check proves the session is alive and still holds every led job's lock.
func (c *coordinator) check(ctx context.Context) error {
	if c.conn == nil || c.runningCount() == 0 {
		return nil
	}
	checking, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	held, err := heldKeys(checking, c.conn)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	for _, job := range c.exclusive {
		if job.running && !held[job.Key] {
			return fmt.Errorf("jobs: leadership of %s is no longer held", job.Name)
		}
	}
	return nil
}

// finish handles a job that returned while it was still the leader: back off
// that job only and unlock it so a peer can take over sooner.
func (c *coordinator) finish(ctx context.Context, finished exit) error {
	job := finished.job
	job.running = false
	job.cancel()
	if time.Since(job.started) >= c.maxBackoff {
		job.failures = 0
	}
	job.failures++
	delay := backoff(c.minBackoff, c.maxBackoff, job.failures)
	job.retryAt = time.Now().Add(delay)
	slog.Error("background job stopped; releasing leadership", "job", job.Name, "mode", Exclusive.String(), "err", describe(finished.err), "retry_in", delay)
	if c.conn == nil {
		return nil
	}
	unlocking, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	return unlock(unlocking, c.conn, job.Key)
}

// release cancels and joins every led job before closing the session. On
// shutdown it unlocks first so a peer need not wait for session teardown.
func (c *coordinator) release(ctx context.Context, reason string) {
	for _, job := range c.exclusive {
		if job.running {
			job.cancel()
		}
	}
	c.group.Wait()
	for running := c.runningCount(); running > 0; running-- {
		finished := <-c.exits
		finished.job.running = false
		slog.Info("background job leadership released", "job", finished.job.Name, "reason", reason)
	}
	if c.conn == nil {
		return
	}
	closing, cancel := context.WithTimeout(context.WithoutCancel(ctx), operationTimeout)
	defer cancel()
	if reason == "shutdown" {
		if _, err := c.conn.Exec(closing, "SELECT pg_advisory_unlock_all()"); err != nil {
			slog.Warn("background job leadership unlock failed; session close releases it", "err", err)
		}
	}
	if err := c.conn.Close(closing); err != nil {
		slog.Warn("close job coordination session failed", "err", err)
	}
	c.conn = nil
}

func (c *coordinator) runningCount() int {
	count := 0
	for _, job := range c.exclusive {
		if job.running {
			count++
		}
	}
	return count
}

func describe(err error) string {
	if err == nil {
		return "unexpected_exit"
	}
	return err.Error()
}

func unlock(ctx context.Context, conn *pgx.Conn, key int64) error {
	var released bool
	if err := conn.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", key).Scan(&released); err != nil {
		return err
	}
	if !released {
		return errors.New("jobs: advisory lock was not held by the coordination session")
	}
	return nil
}

// heldKeys proves the session is alive and still holds each granted lock.
// Bigint advisory keys are split into classid (high) and objid (low) words.
func heldKeys(ctx context.Context, conn *pgx.Conn) (map[int64]bool, error) {
	rows, err := conn.Query(ctx, "SELECT ((classid::bigint << 32) | objid::bigint) FROM pg_locks WHERE locktype = 'advisory' AND objsubid = 1 AND granted AND pid = pg_backend_pid()")
	if err != nil {
		return nil, err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, err
	}
	held := make(map[int64]bool, len(keys))
	for _, key := range keys {
		held[key] = true
	}
	return held, nil
}

// backoff uses equal jitter capped at the maximum.
func backoff(minimum, maximum time.Duration, failures int) time.Duration {
	ceiling := minimum
	for i := 1; i < failures && ceiling < maximum; i++ {
		ceiling *= 2
	}
	ceiling = min(ceiling, maximum)
	if ceiling <= 0 {
		return 0
	}
	return ceiling/2 + time.Duration(rand.Int64N(int64(ceiling/2)+1))
}

// jitter spreads acquisition attempts by ±20% so peers do not poll in lockstep.
func jitter(base time.Duration) time.Duration {
	spread := int64(base) / 5
	if spread <= 0 {
		return base
	}
	return base - time.Duration(spread) + time.Duration(rand.Int64N(2*spread+1))
}

func sleep(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func resetTimer(timer *time.Timer, delay time.Duration) {
	timer.Stop()
	select {
	case <-timer.C:
	default:
	}
	timer.Reset(delay)
}
