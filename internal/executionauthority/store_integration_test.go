//go:build integration

package executionauthority

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/executionauthority/authoritydb"
)

type durableState struct {
	Authority authoritydb.ExecutionAuthority
	Roots     int64
	Updates   int64
	Audits    int64
}

func (f *fixture) state(t *testing.T) durableState {
	t.Helper()
	var state durableState
	var err error
	state.Authority, err = authoritydb.New(f.pool).GetAuthority(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM execution_authority_roots),
		(SELECT count(*) FROM execution_authority_updates),
		(SELECT count(*) FROM audit_events WHERE action LIKE 'execution_authority.%')`).Scan(&state.Roots, &state.Updates, &state.Audits); err != nil {
		t.Fatal(err)
	}
	return state
}

func (f *fixture) unchanged(t *testing.T, before durableState) {
	t.Helper()
	if after := f.state(t); !reflect.DeepEqual(after, before) {
		t.Fatalf("durable authority changed: revision %d->%d roots %d->%d updates %d->%d audits %d->%d delegation_sha256 %x->%x", before.Authority.Revision, after.Authority.Revision, before.Roots, after.Roots, before.Updates, after.Updates, before.Audits, after.Audits, sha256.Sum256(before.Authority.DelegationEnvelope), sha256.Sum256(after.Authority.DelegationEnvelope))
	}
}

func TestInitialPinRestartReplicaAndConfigurationBinding(t *testing.T) {
	f := newFixture(t, 1)
	if err := CheckUnconfigured(f.ctx, f.pool); err != nil {
		t.Fatal(err)
	}
	fresh := f.state(t)
	bad := f.cfg
	bad.BootstrapEnvelope = append(bytes.Clone(bad.BootstrapEnvelope), 'x')
	if _, err := New(f.ctx, f.pool, bad); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("unauthenticated bootstrap: %v", err)
	}
	f.unchanged(t, fresh)
	server := f.open(t)
	initial, err := server.Get(f.ctx)
	if err != nil || initial.Revision != 1 || initial.Delegation != nil || !initial.AcceptedAt.IsZero() || !proto.Equal(initial.Root, f.root) {
		t.Fatalf("initial authority: %+v %v", initial, err)
	}
	if err := CheckUnconfigured(f.ctx, f.pool); !errors.Is(err, ErrConfigured) {
		t.Fatalf("removed configuration: %v", err)
	}
	before := f.state(t)
	if before.Roots != 1 || before.Updates != 0 || before.Audits != 1 {
		t.Fatalf("initial history/audit: %+v", before)
	}
	replica := f.open(t)
	f.unchanged(t, before)
	rotatedTLS := f.cfg
	rotatedTLS.TLSPublicKey = newKey(t).Public()
	if _, err := New(f.ctx, f.pool, rotatedTLS); err != nil {
		t.Fatalf("TLS leaf rotation changed public trust domain: %v", err)
	}
	f.unchanged(t, before)
	request := f.request(t, f.root, f.keys, 1, 7, false)
	if _, err := f.apply(t, server, request, "initial delegation"); err != nil {
		t.Fatal(err)
	}
	seen, err := replica.Get(f.ctx)
	if err != nil || seen.Delegation.GetVersion() != 1 || seen.Delegation.GetMinimumRecoveryEpoch() != 7 || seen.Revision != 2 || seen.AcceptedAt.IsZero() {
		t.Fatalf("replica retained stale state: %+v %v", seen, err)
	}
	restarted := f.open(t)
	loaded, err := restarted.Get(f.ctx)
	if err != nil || loaded.Revision != seen.Revision || !loaded.AcceptedAt.Equal(seen.AcceptedAt) || !proto.Equal(loaded.Root, seen.Root) || !proto.Equal(loaded.Delegation, seen.Delegation) || !bytes.Equal(loaded.DelegationEnvelope, seen.DelegationEnvelope) {
		t.Fatalf("restart state: %+v %v", loaded, err)
	}
	before = f.state(t)
	otherRoot, otherKeys, _ := f.rotate(t, f.root, f.keys)
	for name, cfg := range map[string]Config{
		"unknown newer pin":       f.config(t, otherRoot, otherKeys),
		"same version other keys": func() Config { r := proto.CloneOf(otherRoot); r.Version = 1; return f.config(t, r, otherKeys) }(),
		"different deployment": func() Config {
			r := proto.CloneOf(f.root)
			r.DeploymentId = uuid.NewString()
			return f.config(t, r, f.keys)
		}(),
		"different release domain": func() Config {
			original := f.bundle.ReleaseRootJson
			f.bundle.ReleaseRootJson = releaseRoot(t, newKey(t), f.now.Add(24*time.Hour))
			cfg := f.config(t, f.root, f.keys)
			f.bundle.ReleaseRootJson = original
			return cfg
		}(),
		"execution root reuses server TLS leaf": func() Config {
			cfg := f.cfg
			cfg.TLSPublicKey = f.keys[0].Public()
			return cfg
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(f.ctx, f.pool, cfg); !errors.Is(err, ErrIncompatible) {
				t.Fatalf("incompatible bootstrap accepted: %v", err)
			}
			f.unchanged(t, before)
		})
	}
}

func TestRotationRevocationKnownPinAdvancementAndHistoricalRetry(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	first := f.request(t, f.root, f.keys, 9, 4, false)
	firstReceipt, err := f.apply(t, s, first, "first reason")
	if err != nil {
		t.Fatal(err)
	}
	next, keys, transition := f.rotate(t, f.root, f.keys)
	rotation := f.request(t, next, keys, 10, 5, false)
	rotation.RootTransitions = []*agentv1.ExecutionRootTransition{transition}
	if _, err := f.apply(t, s, rotation, "rotate quorum"); err != nil {
		t.Fatal(err)
	}
	revoke := f.request(t, next, keys, 11, 5, true)
	if _, err := f.apply(t, s, revoke, "revoke online keys"); err != nil {
		t.Fatal(err)
	}
	current, err := s.Get(f.ctx)
	if err != nil || current.Root.GetVersion() != 2 || current.Delegation.GetVersion() != 11 || len(current.Delegation.GetDelegates()) != 0 {
		t.Fatalf("revocation state: %+v %v", current, err)
	}
	cfg := f.config(t, next, keys)
	advanced, err := New(f.ctx, f.pool, cfg)
	if err != nil {
		t.Fatalf("known configured pin advancement: %v", err)
	}
	before := f.state(t)
	replay, err := f.apply(t, advanced, first, "must not replace first reason")
	if err != nil || !proto.Equal(replay, firstReceipt) {
		t.Fatalf("historical retry after newer root/delegation: %+v %v", replay, err)
	}
	f.unchanged(t, before)
	var reason string
	encoded, err := marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if err := f.pool.QueryRow(f.ctx, `SELECT a.reason FROM execution_authority_updates u JOIN audit_events a ON a.id=u.audit_id WHERE u.request_digest=$1`, digest[:]).Scan(&reason); err != nil || reason != "first reason" {
		t.Fatalf("original audit reason: %q %v", reason, err)
	}
	_, catchup, err := f.fetch(t, advanced, f.root, 0, 0, nil)
	if err != nil || len(catchup.GetRootTransitions()) != 1 || !bytes.Equal(catchup.GetDelegationEnvelope(), revoke.GetDelegationEnvelope()) {
		t.Fatalf("old root catchup after pin advancement: %v %v", catchup, err)
	}
}

func TestRejectedUpdatesDoNotChangeRootHistoryOrAudit(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	if _, err := f.apply(t, s, f.request(t, f.root, f.keys, 10, 9, false), "initial"); err != nil {
		t.Fatal(err)
	}
	next, keys, transition := f.rotate(t, f.root, f.keys)
	cases := map[string]*agentv1.UpdateExecutionTrustRequest{
		"strict delegation version":             f.request(t, f.root, f.keys, 10, 10, false),
		"recovery floor independent of version": f.request(t, f.root, f.keys, 11, 8, false),
		"quorum":                                {DelegationEnvelope: f.sign(t, f.delegation(t, f.root, 11, 9, false), f.keys[0])},
		"invalid final delegation rolls back valid rotation": {RootTransitions: []*agentv1.ExecutionRootTransition{transition}, DelegationEnvelope: f.sign(t, f.delegation(t, next, 11, 8, false), keys...)},
	}
	badTransition := proto.CloneOf(transition)
	badTransition.NextQuorumEnvelope = f.sign(t, next, keys[0])
	cases["incomplete new quorum"] = &agentv1.UpdateExecutionTrustRequest{RootTransitions: []*agentv1.ExecutionRootTransition{badTransition}, DelegationEnvelope: f.sign(t, f.delegation(t, next, 11, 9, false), keys...)}
	for _, name := range []string{"expired", "not yet valid"} {
		d := f.delegation(t, f.root, 11, 9, false)
		if name == "expired" {
			d.ExpiresAt = timestamppb.New(f.now.Add(-time.Second))
		} else {
			d.NotBefore = timestamppb.New(f.now.Add(time.Hour))
		}
		cases[name] = &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: f.sign(t, d, f.keys...)}
	}
	before := f.state(t)
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := f.apply(t, s, request, name); !errors.Is(err, ErrRejected) {
				t.Fatalf("invalid authority: %v", err)
			}
			f.unchanged(t, before)
		})
	}
	// Move all recorded acceptance evidence together to model a wall clock
	// rollback independently of partial-state corruption. The future time stays
	// inside the signed validity window, so only the admission clock floor fails.
	if _, err := f.pool.Exec(f.ctx, `WITH updated AS (
		UPDATE execution_authority SET accepted_at=accepted_at+interval '1 hour'
		RETURNING revision, accepted_at
	), admissions AS (
		UPDATE execution_authority_updates u SET accepted_at=e.accepted_at
		FROM updated e WHERE u.revision=e.revision RETURNING u.audit_id, u.accepted_at
	)
	UPDATE audit_events a SET occurred_at=u.accepted_at
	FROM admissions u WHERE a.id=u.audit_id`); err != nil {
		t.Fatal(err)
	}
	before = f.state(t)
	if _, err := f.apply(t, s, f.request(t, f.root, f.keys, 11, 9, false), "clock rollback"); !errors.Is(err, ErrRejected) {
		t.Fatalf("clock rollback: %v", err)
	}
	f.unchanged(t, before)
}

func TestLiveAuthorityRejectsDelegationRollbackAgainstRetainedRevision(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	older := f.request(t, f.root, f.keys, 10, 10, false)
	olderReceipt, err := f.apply(t, s, older, "accepted version ten")
	if err != nil {
		t.Fatal(err)
	}
	newer := f.request(t, f.root, f.keys, 20, 20, true)
	if _, err := f.apply(t, s, newer, "accepted version twenty"); err != nil {
		t.Fatal(err)
	}
	// Simulate partial durable damage after this Store was constructed. Both
	// signed documents remain valid, and only the mutable live envelope rolls
	// back: immutable admission revision, receipt, acceptance time and audit
	// still identify the newer authority. No restart may be needed to fence it.
	if _, err := f.pool.Exec(f.ctx, "UPDATE execution_authority SET delegation_envelope=$1", older.GetDelegationEnvelope()); err != nil {
		t.Fatal(err)
	}
	damaged := f.state(t)
	if damaged.Authority.Revision != 3 || damaged.Updates != 2 {
		t.Fatal("fixture did not retain the newer admission revision")
	}
	t.Run("live administrative read", func(t *testing.T) {
		view, err := s.Get(f.ctx)
		if !errors.Is(err, ErrCorrupt) || view != nil {
			t.Errorf("Get exposed rolled-back revision: returned_snapshot=%t error=%v", view != nil, err)
		}
		f.unchanged(t, damaged)
	})
	t.Run("live device delivery", func(t *testing.T) {
		view, update, err := f.fetch(t, s, f.root, 0, 0, nil)
		if !errors.Is(err, ErrCorrupt) || view != nil || update != nil {
			t.Errorf("device delivery exposed rolled-back revision: returned_snapshot=%t returned_update=%t error=%v", view != nil, update != nil, err)
		}
		f.unchanged(t, damaged)
	})
	t.Run("historical exact retry stays read only", func(t *testing.T) {
		receipt, err := f.apply(t, s, older, "retry must not repair or reset authority")
		if err != nil || !proto.Equal(receipt, olderReceipt) {
			t.Fatalf("historical exact receipt lost: version=%d epoch=%d error=%v", receipt.GetDelegationVersion(), receipt.GetMinimumRecoveryEpoch(), err)
		}
		f.unchanged(t, damaged)
	})
	t.Run("novel intermediate admission", func(t *testing.T) {
		intermediate := f.request(t, f.root, f.keys, 15, 10, false)
		receipt, err := f.apply(t, s, intermediate, "must not lower retained version twenty")
		if !errors.Is(err, ErrCorrupt) || receipt != nil {
			t.Errorf("intermediate authority admitted: version=%d epoch=%d error=%v", receipt.GetDelegationVersion(), receipt.GetMinimumRecoveryEpoch(), err)
		}
		f.unchanged(t, damaged)
	})
}

func TestAuthorityTransactionRollbackIncludesAuditAndMetadata(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	before := f.state(t)
	request := f.request(t, f.root, f.keys, 1, 0, false)
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(f.ctx, tx, request, f.actor, "aborted change"); err != nil {
		_ = tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.unchanged(t, before)
	// The audit FK really participates in the same transaction, rather than a
	// best-effort side effect after authority has already been committed.
	tx, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(f.ctx, tx, request, uuid.New(), "nonexistent actor"); err == nil {
		_ = tx.Rollback(f.ctx)
		t.Fatal("missing audit actor accepted")
	}
	_ = tx.Rollback(f.ctx)
	f.unchanged(t, before)
	if _, err := f.apply(t, s, request, "committed change"); err != nil {
		t.Fatal(err)
	}
	var equal bool
	if err := f.pool.QueryRow(f.ctx, `SELECT e.accepted_at=u.accepted_at AND u.accepted_at=a.occurred_at AND e.revision=u.revision
		FROM execution_authority e JOIN execution_authority_updates u ON u.revision=e.revision JOIN audit_events a ON a.id=u.audit_id`).Scan(&equal); err != nil || !equal {
		t.Fatalf("metadata/audit clock atomicity: %t %v", equal, err)
	}
}

func TestFullUint64AuthorityCounters(t *testing.T) {
	f := newFixture(t, math.MaxUint64-1)
	s := f.open(t)
	first := f.request(t, f.root, f.keys, math.MaxUint64-1, math.MaxUint64-1, false)
	if _, err := f.apply(t, s, first, "full-width initial counters"); err != nil {
		t.Fatal(err)
	}
	next, keys, transition := f.rotate(t, f.root, f.keys)
	last := f.request(t, next, keys, math.MaxUint64, math.MaxUint64, true)
	last.RootTransitions = []*agentv1.ExecutionRootTransition{transition}
	receipt, err := f.apply(t, s, last, "full-width final counters")
	if err != nil || receipt.GetRootVersion() != math.MaxUint64 || receipt.GetDelegationVersion() != math.MaxUint64 || receipt.GetMinimumRecoveryEpoch() != math.MaxUint64 {
		t.Fatalf("uint64 narrowing: %v %v", receipt, err)
	}
	restarted := f.open(t)
	snapshot, update, err := f.fetch(t, restarted, f.root, math.MaxUint64-1, math.MaxUint64-1, first.GetDelegationEnvelope())
	if err != nil || snapshot.Root.GetVersion() != math.MaxUint64 || len(update.GetRootTransitions()) != 1 {
		t.Fatalf("full-width delivery: %v %v %v", snapshot, update, err)
	}
}

func TestMissingStateDoesNotRepinOverRetainedHistory(t *testing.T) {
	f := newFixture(t, 1)
	f.open(t)
	if _, err := f.pool.Exec(f.ctx, "DELETE FROM execution_authority"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(f.ctx, f.pool, f.cfg); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing singleton accepted: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO execution_authority(id) VALUES(true)"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(f.ctx, f.pool, f.cfg); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("orphaned history accepted: %v", err)
	}
	if err := CheckUnconfigured(f.ctx, f.pool); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("orphaned history hidden: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, "DELETE FROM execution_authority_roots"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(f.ctx, f.pool, f.cfg); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("retained initialization audit allowed silent repin: %v", err)
	}
	if err := CheckUnconfigured(f.ctx, f.pool); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("retained initialization audit hidden: %v", err)
	}
}
