// SPDX-License-Identifier: Apache-2.0

//go:build integration

package identity

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// gatedDirectory holds each observation until the test releases it.
type gatedDirectory struct {
	subject  uuid.UUID
	entered  chan struct{}
	release  chan struct{}
	mu       sync.Mutex
	observed int
}

func (d *gatedDirectory) Observe(ctx context.Context, _ string) (directoryObservation, error) {
	d.mu.Lock()
	d.observed++
	d.mu.Unlock()
	d.entered <- struct{}{}
	select {
	case <-d.release:
		return directoryObs(d.subject, time.Time{}, true), nil
	case <-ctx.Done():
		return directoryObservation{}, ctx.Err()
	}
}

// Callers arriving while an observation is in flight never join it: they share
// the next round, whose observation begins after all of them arrived.
func TestFreshAuthorizationJoinsOnlyALaterRound(t *testing.T) {
	svc, ctx, _ := integrationService(t)
	subject, grant := observedAuthorization(t, ctx, svc)
	directory := &gatedDirectory{subject: subject, entered: make(chan struct{}, 8), release: make(chan struct{}, 8)}
	svc.directory = directory
	type result struct {
		authorization *Authorization
		err           error
	}
	authorize := func(results chan<- result) {
		authorization, err := svc.AuthorizeFresh(ctx, grant.actorID, grant.permission)
		results <- result{authorization, err}
	}
	first := make(chan result, 1)
	go authorize(first)
	<-directory.entered
	const later = 5
	joined := make(chan result, later)
	for range later {
		go authorize(joined)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		svc.freshRounds.mu.Lock()
		next := svc.freshRounds.pending[grant.actorID]
		members := 0
		if next != nil && *next != nil {
			members = (*next).members
		}
		svc.freshRounds.mu.Unlock()
		if members == later {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("later callers did not queue for one round: %d", members)
		}
		time.Sleep(5 * time.Millisecond)
	}
	directory.release <- struct{}{}
	initial := <-first
	if initial.err != nil {
		t.Fatal(initial.err)
	}
	<-directory.entered
	directory.release <- struct{}{}
	for range later {
		got := <-joined
		if got.err != nil {
			t.Fatal(got.err)
		}
		if !got.authorization.observedAt.After(initial.authorization.observedAt) {
			t.Fatalf("later caller reused the in-flight observation: %v <= %v", got.authorization.observedAt, initial.authorization.observedAt)
		}
	}
	if directory.observed != 2 {
		t.Fatalf("observations = %d, want one per round", directory.observed)
	}
	for {
		svc.freshRounds.mu.Lock()
		_, running := svc.freshRounds.pending[grant.actorID]
		svc.freshRounds.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("round runner outlived its callers")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Concurrent shared fences of one actor coexist, a revoking observation waits
// for every holder to commit, and a fence taken afterwards sees the revocation.
func TestSharedAuthorizationFenceParallelUntilRevoked(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	subject, grant := observedAuthorization(t, ctx, svc)
	fence := func() pgx.Tx {
		t.Helper()
		tx, err := svc.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cleanupAuthorizationTx(t, tx)
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := svc.LockAuthorizationShared(bounded, tx, grant, grant.permission); err != nil {
			t.Fatalf("shared fence waited on or rejected a concurrent holder: %v", err)
		}
		return tx
	}
	first, second := fence(), fence()
	disable := directoryObs(subject, authorizationDatabaseTime(t, ctx, svc), false)
	revoked := make(chan error, 1)
	go func() { revoked <- applyAuthorizationObservation(ctx, svc, grant.actorID, disable) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_stat_activity a USING (pid)
WHERE NOT l.granted AND a.datname = current_database() AND a.pid <> pg_backend_pid())`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-revoked:
			t.Fatalf("revocation committed beneath shared fences: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("revocation never queued behind the shared fences")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, tx := range []pgx.Tx{first, second} {
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	tx := func() error {
		tx, err := svc.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		return svc.LockAuthorizationShared(ctx, tx, grant, grant.permission)
	}
	if err := tx(); !errors.Is(err, ErrAuthorizationChanged) {
		t.Fatalf("shared fence after revocation = %v, want %v", err, ErrAuthorizationChanged)
	}
}

// countingDirectory answers every observation at once and counts them.
type countingDirectory struct {
	subject  uuid.UUID
	observed atomic.Int32
}

func (d *countingDirectory) Observe(context.Context, string) (directoryObservation, error) {
	d.observed.Add(1)
	return directoryObs(d.subject, time.Time{}, true), nil
}

// The approval inbox and its dashboard count decide every inbox permission
// from one fresh observation (one directory read and principal write, not one
// per permission) and fence them all under one principal lock, where a stale
// or foreign authorization among them still rejects the read.
func TestApprovalInboxSharesOneFreshObservation(t *testing.T) {
	svc, ctx, conn := integrationService(t)
	subject, grant := observedAuthorization(t, ctx, svc)
	directory := &countingDirectory{subject: subject}
	svc.directory = directory
	authorizations, _, err := svc.approvalInboxVisibility(ctx, grant.actorID)
	if err != nil {
		t.Fatal(err)
	}
	if len(authorizations) < 2 {
		t.Fatalf("inbox authorized %d permissions; the fixture must hold several", len(authorizations))
	}
	for _, authorization := range authorizations[1:] {
		if !authorization.observedAt.Equal(authorizations[0].observedAt) {
			t.Fatalf("inbox permissions came from different observations: %v, %v", authorization.observedAt, authorizations[0].observedAt)
		}
	}
	if observed := directory.observed.Load(); observed != 1 {
		t.Fatalf("inbox observations = %d for %d permissions, want one", observed, len(authorizations))
	}
	if _, _, err := svc.CountOpenApprovals(ctx, grant.actorID); err != nil {
		t.Fatal(err)
	}
	if observed := directory.observed.Load(); observed != 2 {
		t.Fatalf("inbox count observations = %d, want one", observed-1)
	}
	lock := func(authorizations []*Authorization) error {
		tx, err := svc.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		return svc.lockInbox(ctx, tx, authorizations)
	}
	if err := lock(authorizations); err != nil {
		t.Fatalf("one-observation inbox fence: %v", err)
	}
	last := len(authorizations) - 1
	stale := *authorizations[last]
	stale.version++
	if err := lock(append(slices.Clone(authorizations[:last]), &stale)); !errors.Is(err, ErrAuthorizationChanged) {
		t.Fatalf("inbox fence with one stale authorization = %v, want %v", err, ErrAuthorizationChanged)
	}
	_, foreign := observedAuthorization(t, ctx, svc)
	if err := lock(append(slices.Clone(authorizations), foreign)); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("inbox fence with another actor's authorization = %v, want %v", err, ErrAuthorizationDenied)
	}
	if _, err := conn.Exec(ctx, `UPDATE principals SET authorization_version = authorization_version + 1 WHERE id = $1`, grant.actorID); err != nil {
		t.Fatal(err)
	}
	if err := lock(authorizations); !errors.Is(err, ErrAuthorizationChanged) {
		t.Fatalf("inbox fence after an authority change = %v, want %v", err, ErrAuthorizationChanged)
	}
}
