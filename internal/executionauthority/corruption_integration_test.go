//go:build integration

package executionauthority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"

	"lindm/internal/executionauthority/authoritydb"
)

func TestLiveAuthorityBindsAdmissionEvidence(t *testing.T) {
	for _, name := range []string{
		"singleton acceptance time",
		"retained request digest",
		"retained receipt counters",
		"byte-distinct retained envelope",
		"same-version root substitution",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1)
			s := f.open(t)
			request := f.request(t, f.root, f.keys, 20, 20, false)
			receipt, err := f.apply(t, s, request, "accepted authority")
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "singleton acceptance time":
				_, err = f.pool.Exec(f.ctx, "UPDATE execution_authority SET accepted_at=accepted_at+interval '1 second'")
			case "retained request digest":
				digest := sha256.Sum256([]byte("not the retained signed request"))
				_, err = f.pool.Exec(f.ctx, "UPDATE execution_authority_updates SET request_digest=$1 WHERE revision=2", digest[:])
			case "retained receipt counters":
				changed := proto.CloneOf(receipt)
				changed.DelegationVersion = 15
				changed.MinimumRecoveryEpoch = 10
				encoded, marshalErr := marshal(changed)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				_, err = f.pool.Exec(f.ctx, "UPDATE execution_authority_updates SET receipt_document=$1 WHERE revision=2", encoded)
			case "byte-distinct retained envelope":
				// The signature and payload still verify, as does the recomputed
				// request digest. The live envelope must nevertheless match the
				// exact admitted signed bytes, not just equivalent delegation data.
				changed := proto.CloneOf(request)
				changed.DelegationEnvelope = append(changed.DelegationEnvelope, ' ')
				encoded, marshalErr := marshal(changed)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				digest := sha256.Sum256(encoded)
				_, err = f.pool.Exec(f.ctx, "UPDATE execution_authority_updates SET request_document=$1,request_digest=$2 WHERE revision=2", encoded, digest[:])
			case "same-version root substitution":
				// Lowering the root threshold leaves the delegation signature
				// mathematically valid, but this root was never admitted.
				changed := proto.CloneOf(f.root)
				changed.Threshold = 1
				encoded, marshalErr := marshal(changed)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				_, err = f.pool.Exec(f.ctx, "UPDATE execution_authority SET root_document=$1", encoded)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := f.state(t)
			if view, err := s.Get(f.ctx); !errors.Is(err, ErrCorrupt) || view != nil {
				t.Errorf("corrupt live admission exposed: returned_snapshot=%t error=%v", view != nil, err)
			}
			if view, update, err := f.fetch(t, s, f.root, 0, 0, nil); !errors.Is(err, ErrCorrupt) || view != nil || update != nil {
				t.Errorf("corrupt admission delivered: returned_snapshot=%t returned_update=%t error=%v", view != nil, update != nil, err)
			}
			novel := f.request(t, f.root, f.keys, 30, 30, true)
			if receipt, err := f.apply(t, s, novel, "must not build on corrupt evidence"); !errors.Is(err, ErrCorrupt) || receipt != nil {
				t.Errorf("novel mutation accepted corrupt admission: version=%d epoch=%d error=%v", receipt.GetDelegationVersion(), receipt.GetMinimumRecoveryEpoch(), err)
			}
			f.unchanged(t, before)
		})
	}
}

func TestSnapshotBindsCapturedRevisionNotLaterHead(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	q := authoritydb.New(f.pool)
	seed, err := q.GetAuthority(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	first := f.request(t, f.root, f.keys, 10, 10, false)
	if _, err := f.apply(t, s, first, "captured authority"); err != nil {
		t.Fatal(err)
	}
	initial, err := s.snapshot(f.ctx, q, seed)
	if err != nil || initial.Revision != 1 || initial.Delegation != nil || !initial.AcceptedAt.IsZero() || !proto.Equal(initial.Root, f.root) {
		t.Fatalf("captured root-only revision displaced by first delegation: returned_snapshot=%t error=%v", initial != nil, err)
	}
	captured, err := q.GetAuthority(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	second := f.request(t, f.root, f.keys, 20, 20, true)
	if _, err := f.apply(t, s, second, "new head after snapshot read"); err != nil {
		t.Fatal(err)
	}
	// Model the real READ COMMITTED interleaving deterministically: another
	// replica commits between the singleton read and its admission point lookup.
	view, err := s.snapshot(f.ctx, q, captured)
	if err != nil || view.Revision != 2 || view.Delegation.GetVersion() != 10 || view.Delegation.GetMinimumRecoveryEpoch() != 10 {
		t.Fatalf("captured revision displaced by newer admission: returned_snapshot=%t error=%v", view != nil, err)
	}
	if !bytes.Equal(view.DelegationEnvelope, first.GetDelegationEnvelope()) {
		t.Fatal("captured snapshot changed its admitted delegation")
	}
	latest, err := s.Get(f.ctx)
	if err != nil || latest.Revision != 3 || latest.Delegation.GetVersion() != 20 {
		t.Fatalf("new head unreadable after coherent historical snapshot: returned_snapshot=%t error=%v", latest != nil, err)
	}
}

func TestLiveInitialAuthorityRejectsRootSubstitution(t *testing.T) {
	f := newFixture(t, 1)
	s := f.open(t)
	attackerKeys := []ed25519.PrivateKey{newKey(t), newKey(t)}
	substitute := proto.CloneOf(f.root)
	substitute.Keys = []*agentv1.ExecutionKey{
		publicKey(t, attackerKeys[0]),
		publicKey(t, attackerKeys[1]),
	}
	encoded, err := marshal(substitute)
	if err != nil {
		t.Fatal(err)
	}
	// Only the live initial root changes. The original signed bootstrap,
	// retained root digest/document, position and seed audit still pin f.root.
	if _, err := f.pool.Exec(f.ctx, "UPDATE execution_authority SET root_document=$1", encoded); err != nil {
		t.Fatal(err)
	}
	damaged := f.state(t)
	if damaged.Authority.Revision != 1 || damaged.Updates != 0 || damaged.Audits != 1 {
		t.Fatal("fixture did not remain at the initial root-only revision")
	}
	t.Run("live initial read", func(t *testing.T) {
		view, err := s.Get(f.ctx)
		if !errors.Is(err, ErrCorrupt) || view != nil {
			t.Errorf("substituted initial root exposed: returned_snapshot=%t error=%v", view != nil, err)
		}
		f.unchanged(t, damaged)
	})
	t.Run("live initial device view", func(t *testing.T) {
		view, update, err := f.fetch(t, s, f.root, 0, 0, nil)
		if !errors.Is(err, ErrCorrupt) || view != nil || update != nil {
			t.Errorf("substituted initial root exposed to device: returned_snapshot=%t returned_update=%t error=%v", view != nil, update != nil, err)
		}
		f.unchanged(t, damaged)
	})
	t.Run("attacker quorum first delegation", func(t *testing.T) {
		request := f.request(t, substitute, attackerKeys, 1, 0, false)
		receipt, err := f.apply(t, s, request, "must not authorize substituted initial keys")
		if !errors.Is(err, ErrCorrupt) || receipt != nil {
			t.Errorf("attacker quorum admitted first delegation: version=%d epoch=%d error=%v", receipt.GetDelegationVersion(), receipt.GetMinimumRecoveryEpoch(), err)
		}
		f.unchanged(t, damaged)
	})
}

func TestLiveInitialAuthorityBindsSeedMetadata(t *testing.T) {
	for _, name := range []string{
		"singleton acceptance time",
		"initialization time",
		"retained root acceptance time",
		"noninitial retained position",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1)
			s := f.open(t)
			var err error
			switch name {
			case "singleton acceptance time":
				_, err = f.pool.Exec(f.ctx, "UPDATE execution_authority SET accepted_at=accepted_at+interval '1 second'")
			case "initialization time":
				_, err = f.pool.Exec(f.ctx, "UPDATE execution_authority SET initialized_at=initialized_at-interval '1 second'")
			case "retained root acceptance time":
				_, err = f.pool.Exec(f.ctx, "UPDATE execution_authority_roots SET accepted_at=accepted_at-interval '1 second' WHERE position=1")
			case "noninitial retained position":
				// Keep the singleton count equal to the retained root position:
				// root-only state must specifically bind the initial position,
				// not merely two mutually consistent noninitial counters.
				_, err = f.pool.Exec(f.ctx, `WITH moved AS (
					UPDATE execution_authority_roots SET position=2,transition_document=$1
					WHERE position=1 RETURNING position
				) UPDATE execution_authority SET root_count=(SELECT position FROM moved)`, []byte{1})
			}
			if err != nil {
				t.Fatal(err)
			}
			before := f.state(t)
			if view, err := s.Get(f.ctx); !errors.Is(err, ErrCorrupt) || view != nil {
				t.Errorf("corrupt initial metadata exposed: returned_snapshot=%t error=%v", view != nil, err)
			}
			if view, update, err := f.fetch(t, s, f.root, 0, 0, nil); !errors.Is(err, ErrCorrupt) || view != nil || update != nil {
				t.Errorf("corrupt initial metadata delivered: returned_snapshot=%t returned_update=%t error=%v", view != nil, update != nil, err)
			}
			request := f.request(t, f.root, f.keys, 1, 0, false)
			if receipt, err := f.apply(t, s, request, "must not build on damaged seed metadata"); !errors.Is(err, ErrCorrupt) || receipt != nil {
				t.Errorf("first delegation accepted damaged seed metadata: version=%d error=%v", receipt.GetDelegationVersion(), err)
			}
			f.unchanged(t, before)
		})
	}
}
