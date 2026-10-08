package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

type executionFixture struct {
	authority *Authority
	verifier  *ExecutionVerifier
	root      *agentv1.ExecutionRoot
	keys      []ed25519.PrivateKey
	reserved  []ed25519.PrivateKey
	now       time.Time
}

func newExecutionFixture(t *testing.T, count int) executionFixture {
	t.Helper()
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	f := executionFixture{authority: a, now: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}
	f.root = &agentv1.ExecutionRoot{DeploymentId: uuid.NewString(), Version: 1, Threshold: uint32(count), NotBefore: timestamppb.New(f.now.Add(-time.Hour)), ExpiresAt: timestamppb.New(f.now.Add(24 * time.Hour))}
	for range count {
		key := testKey(t)
		f.keys = append(f.keys, key)
		f.root.Keys = append(f.root.Keys, executionTestKey(t, key))
	}
	rootJSON, err := protojson.Marshal(f.root)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(rootJSON)
	f.reserved = []ed25519.PrivateKey{testKey(t), testKey(t), testKey(t)}
	bundle := &agentv1.BootstrapBundle{
		BundleId: uuid.NewString(), DeploymentId: f.root.GetDeploymentId(),
		EnrollmentOrigin: "https://enroll.example", DeviceOrigin: "https://devices.example",
		TransportCaPem:       testCA(t, f.reserved[0], f.now, x509.ExtKeyUsageServerAuth),
		DeviceCaPem:          testCA(t, f.reserved[1], f.now, x509.ExtKeyUsageClientAuth),
		ExecutionRootVersion: 1, ExecutionRootSha256: digest[:],
		ReleaseRootJson: testReleaseRoot(t, f.reserved[2], f.now.Add(time.Hour)),
		NotBefore:       timestamppb.New(f.now.Add(-time.Minute)), ExpiresAt: timestamppb.New(f.now.Add(time.Hour)),
	}
	bootstrap, err := a.VerifyBootstrap(t.Context(), rootJSON, executionSign(t, a, bundle, f.keys...), f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.verifier, err = a.NewExecutionVerifier(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func executionTestKey(t *testing.T, key ed25519.PrivateKey) *agentv1.ExecutionKey {
	t.Helper()
	public := ed25519.PublicKey(key[ed25519.SeedSize:])
	id, err := KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.ExecutionKey{KeyId: id, PublicKey: public}
}

func executionSign(t *testing.T, a *Authority, message proto.Message, keys ...ed25519.PrivateKey) []byte {
	t.Helper()
	envelope, err := a.Sign(t.Context(), message, keys...)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestExecutionRootTransitionRequiresBothQuorums(t *testing.T) {
	f := newExecutionFixture(t, 2)
	nextKeys := []ed25519.PrivateKey{testKey(t), testKey(t)}
	next := proto.CloneOf(f.root)
	next.Version++
	next.Keys = []*agentv1.ExecutionKey{executionTestKey(t, nextKeys[0]), executionTestKey(t, nextKeys[1])}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.ExecutionRoot)
		old    []ed25519.PrivateKey
		new    []ed25519.PrivateKey
		at     time.Time
		valid  bool
	}{
		{name: "both quorums", old: f.keys, new: nextKeys, at: f.now, valid: true},
		{name: "old quorum absent", old: nextKeys, new: nextKeys, at: f.now},
		{name: "old quorum incomplete", old: f.keys[:1], new: nextKeys, at: f.now},
		{name: "new quorum absent", old: f.keys, new: f.keys, at: f.now},
		{name: "new quorum incomplete", old: f.keys, new: nextKeys[:1], at: f.now},
		{name: "deployment substitution", old: f.keys, new: nextKeys, at: f.now, change: func(r *agentv1.ExecutionRoot) { r.DeploymentId = uuid.NewString() }},
		{name: "version rollback", old: f.keys, new: nextKeys, at: f.now, change: func(r *agentv1.ExecutionRoot) { r.Version = 1 }},
		{name: "version gap", old: f.keys, new: nextKeys, at: f.now, change: func(r *agentv1.ExecutionRoot) { r.Version = 3 }},
		{name: "next root expired", old: f.keys, new: nextKeys, at: f.now, change: func(r *agentv1.ExecutionRoot) { r.ExpiresAt = timestamppb.New(f.now) }},
		{name: "current root expired", old: f.keys, new: nextKeys, at: f.root.GetExpiresAt().AsTime()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proto.CloneOf(next)
			if tc.change != nil {
				tc.change(candidate)
			}
			transition := &agentv1.ExecutionRootTransition{
				PreviousQuorumEnvelope: executionSign(t, f.authority, candidate, tc.old...),
				NextQuorumEnvelope:     executionSign(t, f.authority, candidate, tc.new...),
			}
			before := proto.CloneOf(f.root)
			accepted, err := f.verifier.VerifyRootTransition(t.Context(), f.root, transition, tc.at)
			if tc.valid {
				if err != nil || !proto.Equal(accepted, candidate) {
					t.Fatalf("accepted root = %v, error = %v", accepted, err)
				}
			} else if err == nil || accepted != nil {
				t.Fatalf("accepted unauthorized root: %v", err)
			}
			if !proto.Equal(f.root, before) {
				t.Fatal("verification mutated the trusted root")
			}
		})
	}
	other := proto.CloneOf(next)
	other.ExpiresAt = timestamppb.New(f.now.Add(23 * time.Hour))
	mismatched := &agentv1.ExecutionRootTransition{PreviousQuorumEnvelope: executionSign(t, f.authority, next, f.keys...), NextQuorumEnvelope: executionSign(t, f.authority, other, nextKeys...)}
	if _, err := f.verifier.VerifyRootTransition(t.Context(), f.root, mismatched, f.now); err == nil {
		t.Fatal("quorums endorsed different root contents")
	}
}

func TestExecutionRotationSupportsDisjointMaximumQuorums(t *testing.T) {
	f := newExecutionFixture(t, 16)
	next := proto.CloneOf(f.root)
	next.Version++
	next.Keys = nil
	var nextKeys []ed25519.PrivateKey
	for range 16 {
		key := testKey(t)
		nextKeys = append(nextKeys, key)
		next.Keys = append(next.Keys, executionTestKey(t, key))
	}
	transition := &agentv1.ExecutionRootTransition{PreviousQuorumEnvelope: executionSign(t, f.authority, next, f.keys...), NextQuorumEnvelope: executionSign(t, f.authority, next, nextKeys...)}
	accepted, err := f.verifier.VerifyRootTransition(t.Context(), f.root, transition, f.now)
	if err != nil || !proto.Equal(accepted, next) {
		t.Fatalf("valid disjoint 16-key quorums rejected: %v", err)
	}
}

func TestExecutionTrustSeparatesTLSReleaseAndRootRoles(t *testing.T) {
	f := newExecutionFixture(t, 2)
	for i, key := range f.reserved {
		next := proto.CloneOf(f.root)
		next.Version++
		next.Threshold = 1
		next.Keys = []*agentv1.ExecutionKey{executionTestKey(t, key)}
		transition := &agentv1.ExecutionRootTransition{PreviousQuorumEnvelope: executionSign(t, f.authority, next, f.keys...), NextQuorumEnvelope: executionSign(t, f.authority, next, key)}
		if _, err := f.verifier.VerifyRootTransition(t.Context(), f.root, transition, f.now); err == nil {
			t.Fatalf("reserved key %d accepted as new execution root", i)
		}
	}
	for i, key := range append(f.reserved, f.keys...) {
		delegation := executionTestDelegation(t, f, key)
		if _, err := f.verifier.VerifyDelegation(t.Context(), f.root, executionSign(t, f.authority, delegation, f.keys...), 0, 0, f.now); err == nil {
			t.Fatalf("reserved/offline key %d accepted as online signer", i)
		}
	}
}

func executionTestDelegation(t *testing.T, f executionFixture, key ed25519.PrivateKey) *agentv1.ExecutionDelegation {
	t.Helper()
	return &agentv1.ExecutionDelegation{
		DeploymentId: f.root.GetDeploymentId(), RootVersion: 1, Version: 2, MinimumRecoveryEpoch: 3,
		NotBefore: timestamppb.New(f.now.Add(-time.Minute)), ExpiresAt: timestamppb.New(f.now.Add(time.Hour)),
		Delegates: []*agentv1.ExecutionDelegate{{Key: executionTestKey(t, key), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: []string{"systemd.service.v1"}}},
	}
}

func TestExecutionDelegationRollbackAndRevocation(t *testing.T) {
	f := newExecutionFixture(t, 2)
	for _, tc := range []struct {
		name   string
		change func(*agentv1.ExecutionDelegation)
		valid  bool
	}{
		{name: "scoped online key", valid: true},
		{name: "revoke all online keys", valid: true, change: func(d *agentv1.ExecutionDelegation) { d.Delegates = nil }},
		{name: "old version", change: func(d *agentv1.ExecutionDelegation) { d.Version = 1 }},
		{name: "old recovery epoch", change: func(d *agentv1.ExecutionDelegation) { d.MinimumRecoveryEpoch = 2 }},
		{name: "other deployment", change: func(d *agentv1.ExecutionDelegation) { d.DeploymentId = uuid.NewString() }},
		{name: "other root", change: func(d *agentv1.ExecutionDelegation) { d.RootVersion = 2 }},
		{name: "expired", change: func(d *agentv1.ExecutionDelegation) { d.ExpiresAt = timestamppb.New(f.now) }},
		{name: "future", change: func(d *agentv1.ExecutionDelegation) { d.NotBefore = timestamppb.New(f.now.Add(time.Minute)) }},
		{name: "outlives root", change: func(d *agentv1.ExecutionDelegation) { d.ExpiresAt = timestamppb.New(f.now.Add(25 * time.Hour)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delegation := executionTestDelegation(t, f, testKey(t))
			if tc.change != nil {
				tc.change(delegation)
			}
			accepted, err := f.verifier.VerifyDelegation(t.Context(), f.root, executionSign(t, f.authority, delegation, f.keys...), 1, 3, f.now)
			if tc.valid {
				if err != nil || !proto.Equal(accepted, delegation) {
					t.Fatalf("valid delegation rejected: %v", err)
				}
			} else if err == nil || accepted != nil {
				t.Fatalf("accepted invalid delegation: %v", err)
			}
		})
	}
}
