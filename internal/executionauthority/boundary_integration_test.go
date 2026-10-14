// SPDX-License-Identifier: Apache-2.0

//go:build integration

package executionauthority

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/executionauthority/authoritydb"
)

func TestRetainedByteCapacityAdmitsExactBoundaryAndPreservesReplay(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	first := f.request(t, f.root, f.keys, 1, 1, false)
	firstReceipt, err := f.apply(t, s, first, "first retained update")
	if err != nil {
		t.Fatal(err)
	}
	next, keys, transition := f.rotate(t, f.root, f.keys)
	last := f.request(t, next, keys, 2, 2, true)
	last.RootTransitions = []*agentv1.ExecutionRootTransition{transition}
	delegation, err := s.verifier.VerifyDelegation(f.ctx, next, last.GetDelegationEnvelope(), 1, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	requestBytes, err := marshal(last)
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, err := marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	transitionBytes, err := marshal(transition)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := marshal(executionReceipt(next, delegation))
	if err != nil {
		t.Fatal(err)
	}
	cost := int64(len(requestBytes) + len(rootBytes) + len(transitionBytes) + len(receiptBytes))
	// Reserve the already-consumed portion of the finite budget directly in the
	// isolated DB. This targets admission arithmetic without generating tens of
	// megabytes of irrelevant signed fixtures; the boundary change and replay
	// below still execute the real crypto, SQL transaction and audit paths.
	if _, err := f.pool.Exec(f.ctx, "UPDATE execution_authority SET retained_bytes=$1", int64(maxRetainedBytes)-cost+1); err != nil {
		t.Fatal(err)
	}
	before := f.state(t)
	if _, err := f.apply(t, s, last, "one byte beyond capacity"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("one-byte overflow admission: %v", err)
	}
	f.unchanged(t, before)
	if _, err := f.pool.Exec(f.ctx, "UPDATE execution_authority SET retained_bytes=retained_bytes-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.apply(t, s, last, "exact capacity"); err != nil {
		t.Fatalf("exact boundary rejected: %v", err)
	}
	before = f.state(t)
	if before.Authority.RetainedBytes != maxRetainedBytes || before.Authority.RootCount != 2 || before.Updates != 2 || before.Audits != 3 {
		t.Fatalf("capacity accounting omitted retained objects: %+v", before)
	}
	if _, err := f.apply(t, s, f.request(t, next, keys, 3, 2, true), "beyond full capacity"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("full history admitted another mutation: %v", err)
	}
	f.unchanged(t, before)
	replay, err := f.apply(t, s, first, "capacity does not erase exact retry")
	if err != nil || !proto.Equal(replay, firstReceipt) {
		t.Fatalf("old retry at capacity: %v %v", replay, err)
	}
	f.unchanged(t, before)
}

func TestMutationClockIsSampledAfterSingletonLock(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	before := f.state(t)
	blocker, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(f.ctx) }()
	if _, err := authoritydb.New(blocker).LockAuthority(f.ctx); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 8*time.Second)
	defer cancel()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	var start, expiry time.Time
	if err := tx.QueryRow(ctx, "SELECT now(), clock_timestamp()+interval '1 second'").Scan(&start, &expiry); err != nil {
		t.Fatal(err)
	}
	if !start.Before(expiry) {
		t.Fatal("fixture transaction started after expiry")
	}
	d := f.delegation(t, f.root, 1, 0, false)
	d.ExpiresAt = timestamppb.New(expiry)
	request := &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: f.sign(t, d, f.keys...)}
	result := make(chan error, 1)
	go func() {
		_, err := s.Apply(ctx, tx, request, f.actor, "expired while queued for mutation lock")
		result <- err
	}()
	if _, err := blocker.Exec(ctx, "SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.05)", expiry); err != nil {
		_ = blocker.Rollback(f.ctx)
		<-result
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		<-result
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrRejected) {
		t.Fatalf("authority accepted against transaction-start time: %v", err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.unchanged(t, before)
}
