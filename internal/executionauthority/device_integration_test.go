//go:build integration

package executionauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/executionauthority/authoritydb"
	"lindm/internal/trust"
)

func TestDeviceHintsCatchupAndEightHopBoundary(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	initial, update, err := f.fetch(t, s, f.root, 0, 0, nil)
	if err != nil || update != nil || initial.Delegation != nil {
		t.Fatalf("initial device authority: %+v %v %v", initial, update, err)
	}
	root, keys := f.root, f.keys
	var second *agentv1.ExecutionRoot
	var latest *agentv1.UpdateExecutionTrustRequest
	for version := uint64(2); version <= 10; version++ {
		next, nextKeys, transition := f.rotate(t, root, keys)
		latest = f.request(t, next, nextKeys, version, version, false)
		latest.RootTransitions = []*agentv1.ExecutionRootTransition{transition}
		if _, err := f.apply(t, s, latest, "retained root rotation"); err != nil {
			t.Fatal(err)
		}
		root, keys = next, nextKeys
		if version == 2 {
			second = root
		}
	}
	before := f.state(t)
	if _, _, err := f.fetch(t, s, f.root, 0, 0, nil); !errors.Is(err, ErrReprovisioning) {
		t.Fatalf("nine-hop delivery must fail explicitly: %v", err)
	}
	snapshot, catchup, err := f.fetch(t, s, second, 0, 0, nil)
	if err != nil || len(catchup.GetRootTransitions()) != 8 || !proto.Equal(snapshot.Root, root) || snapshot.Delegation.GetVersion() != 10 || !bytes.Equal(catchup.GetDelegationEnvelope(), latest.GetDelegationEnvelope()) {
		t.Fatalf("eight-hop delivery: %+v %+v %v", snapshot, catchup, err)
	}
	// Verify the delivered chain as a device would, including disjoint quorums.
	current := second
	for _, transition := range catchup.GetRootTransitions() {
		current, err = s.verifier.VerifyRootTransition(f.ctx, current, transition, time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	delegation, err := s.verifier.VerifyDelegation(f.ctx, current, catchup.GetDelegationEnvelope(), 0, 0, time.Now())
	if err != nil || !proto.Equal(delegation, snapshot.Delegation) {
		t.Fatalf("advertised snapshot differs from delivered authority: %v", err)
	}
	if _, update, err := f.fetch(t, s, root, 10, 10, latest.GetDelegationEnvelope()); err != nil || update != nil {
		t.Fatalf("already current device: %v %v", update, err)
	}
	changed := proto.CloneOf(root)
	changed.ExpiresAt = timestamppb.New(root.GetExpiresAt().AsTime().Add(-time.Minute))
	unknown := proto.CloneOf(root)
	unknown.Version = 11
	for _, tc := range []struct {
		name     string
		root     *agentv1.ExecutionRoot
		version  uint64
		epoch    uint64
		envelope []byte
		want     error
	}{
		{"same root version different hash", changed, 0, 0, nil, ErrIncompatible},
		{"server root behind", unknown, 0, 0, nil, ErrServerBehind},
		{"server delegation behind", root, 11, 10, latest.GetDelegationEnvelope(), ErrServerBehind},
		{"server recovery behind", root, 10, 11, latest.GetDelegationEnvelope(), ErrServerBehind},
		{"same delegation version different hash", root, 10, 10, []byte("other envelope"), ErrIncompatible},
		{"inconsistent current recovery", root, 10, 9, latest.GetDelegationEnvelope(), ErrIncompatible},
		{"inconsistent root and delegation", second, 10, 10, latest.GetDelegationEnvelope(), ErrIncompatible},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := f.fetch(t, s, tc.root, tc.version, tc.epoch, tc.envelope); !errors.Is(err, tc.want) {
				t.Fatalf("device hint error: %v want %v", err, tc.want)
			}
		})
	}
	f.unchanged(t, before)
}

func TestForDeviceDoesNotAcquireGlobalMutationLock(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	request := f.request(t, f.root, f.keys, 1, 0, false)
	if _, err := f.apply(t, s, request, "initial"); err != nil {
		t.Fatal(err)
	}
	blocker, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(f.ctx) }()
	if _, err := authoritydb.New(blocker).LockAuthority(f.ctx); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	digest, err := trust.ExecutionRootDigest(f.root)
	if err != nil {
		t.Fatal(err)
	}
	view, update, err := s.ForDevice(ctx, tx, 1, 0, 0, digest[:], nil)
	if err != nil || view.Delegation.GetVersion() != 1 || !bytes.Equal(update.GetDelegationEnvelope(), request.GetDelegationEnvelope()) {
		t.Fatalf("device read waited on authority mutation lock: %v %v %v", view, update, err)
	}
}

func TestExpiredAcceptedDelegationRemainsReadableAndRetryable(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	var expiry time.Time
	if err := f.pool.QueryRow(f.ctx, "SELECT clock_timestamp()+interval '1 second'").Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	d := f.delegation(t, f.root, 1, 1, false)
	d.ExpiresAt = timestamppb.New(expiry)
	first := &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: f.sign(t, d, f.keys...)}
	receipt, err := f.apply(t, s, first, "short authority")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.05)", expiry); err != nil {
		t.Fatal(err)
	}
	restarted := f.open(t)
	before := f.state(t)
	view, err := restarted.Get(f.ctx)
	if err != nil || view.Delegation.GetVersion() != 1 {
		t.Fatalf("historical read after expiry: %+v %v", view, err)
	}
	if _, _, err := f.fetch(t, restarted, f.root, 0, 0, nil); !errors.Is(err, ErrReprovisioning) {
		t.Fatalf("expired delivery: %v", err)
	}
	replay, err := f.apply(t, restarted, first, "expired retry")
	if err != nil || !proto.Equal(replay, receipt) {
		t.Fatalf("expired exact retry: %v %v", replay, err)
	}
	f.unchanged(t, before)
	second := f.request(t, f.root, f.keys, 2, 1, true)
	if _, err := f.apply(t, restarted, second, "renewed revocation"); err != nil {
		t.Fatal(err)
	}
	before = f.state(t)
	replay, err = f.apply(t, f.open(t), first, "expired and superseded retry")
	if err != nil || !proto.Equal(replay, receipt) {
		t.Fatalf("superseded expired exact retry: %v %v", replay, err)
	}
	f.unchanged(t, before)
	// Valid but byte-distinct envelope serialization is not an exact retry.
	altered := proto.CloneOf(first)
	altered.DelegationEnvelope = append(altered.DelegationEnvelope, ' ')
	if _, err := f.apply(t, restarted, altered, "different bytes"); !errors.Is(err, ErrRejected) {
		t.Fatalf("byte-distinct retry: %v", err)
	}
	f.unchanged(t, before)
}

func TestExpiredIntermediateRootRequiresReprovisioning(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	second, secondKeys, _ := f.rotate(t, f.root, f.keys)
	var expiry time.Time
	if err := f.pool.QueryRow(f.ctx, "SELECT clock_timestamp()+interval '2 seconds'").Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	second.ExpiresAt = timestamppb.New(expiry)
	transition := &agentv1.ExecutionRootTransition{PreviousQuorumEnvelope: f.sign(t, second, f.keys...), NextQuorumEnvelope: f.sign(t, second, secondKeys...)}
	d := f.delegation(t, second, 1, 0, false)
	d.ExpiresAt = timestamppb.New(expiry)
	request := &agentv1.UpdateExecutionTrustRequest{RootTransitions: []*agentv1.ExecutionRootTransition{transition}, DelegationEnvelope: f.sign(t, d, secondKeys...)}
	if _, err := f.apply(t, s, request, "short intermediate"); err != nil {
		t.Fatal(err)
	}
	third, thirdKeys, _ := f.rotate(t, second, secondKeys)
	third.ExpiresAt = proto.CloneOf(f.root.ExpiresAt)
	transition = &agentv1.ExecutionRootTransition{PreviousQuorumEnvelope: f.sign(t, third, secondKeys...), NextQuorumEnvelope: f.sign(t, third, thirdKeys...)}
	request = f.request(t, third, thirdKeys, 2, 0, false)
	request.RootTransitions = []*agentv1.ExecutionRootTransition{transition}
	if _, err := f.apply(t, s, request, "fresh final root"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.05)", expiry); err != nil {
		t.Fatal(err)
	}
	before := f.state(t)
	if _, _, err := f.fetch(t, f.open(t), f.root, 0, 0, nil); !errors.Is(err, ErrReprovisioning) {
		t.Fatalf("expired intermediate delivered: %v", err)
	}
	f.unchanged(t, before)
}

func TestConcurrentDeliveryUsesOneAuthorityRevision(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	first := f.request(t, f.root, f.keys, 1, 0, false)
	if _, err := f.apply(t, s, first, "initial"); err != nil {
		t.Fatal(err)
	}
	requests := make([]*agentv1.UpdateExecutionTrustRequest, 0, 5)
	root, keys := f.root, f.keys
	for version := uint64(2); version <= 6; version++ {
		next, nextKeys, transition := f.rotate(t, root, keys)
		request := f.request(t, next, nextKeys, version, version, false)
		request.RootTransitions = []*agentv1.ExecutionRootTransition{transition}
		requests = append(requests, request)
		root, keys = next, nextKeys
	}
	finished := make(chan error, 1)
	joined := false
	defer func() {
		if !joined {
			<-finished
		}
	}()
	go func() {
		for _, request := range requests {
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				finished <- err
				return
			}
			_, err = s.Apply(f.ctx, tx, request, f.actor, "concurrent rotation")
			if err == nil {
				err = tx.Commit(f.ctx)
			} else {
				_ = tx.Rollback(f.ctx)
			}
			if err != nil {
				finished <- err
				return
			}
		}
		finished <- nil
	}()
	for range 30 {
		view, request, err := f.fetch(t, s, f.root, 0, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		current := f.root
		for _, transition := range request.GetRootTransitions() {
			current, err = s.verifier.VerifyRootTransition(f.ctx, current, transition, time.Now())
			if err != nil {
				t.Fatal(err)
			}
		}
		delegation, err := s.verifier.VerifyDelegation(f.ctx, current, request.GetDelegationEnvelope(), 0, 0, time.Now())
		if err != nil || !proto.Equal(current, view.Root) || !proto.Equal(delegation, view.Delegation) || !bytes.Equal(view.DelegationEnvelope, request.GetDelegationEnvelope()) {
			t.Fatalf("mixed authority snapshot/update: %+v %+v %v", view, request, err)
		}
	}
	writeErr := <-finished
	joined = true
	if err := writeErr; err != nil {
		t.Fatal(err)
	}
	// No device fetch inserts any observation or success receipt.
	state := f.state(t)
	if state.Updates != 6 || state.Audits != 7 {
		t.Fatalf("device fetch mutated retained history: %+v", state)
	}
}

func TestMalformedDeviceDigestIsRejectedBeforeSelection(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	digest := sha256.Sum256([]byte("not an authenticated root"))
	if _, _, err := s.ForDevice(f.ctx, tx, 1, 0, 0, digest[:], nil); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("unknown root hash: %v", err)
	}
	if _, _, err := s.ForDevice(f.ctx, tx, 1, 0, 0, digest[:4], nil); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("short root hash: %v", err)
	}
}
