package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

type serviceAuthorityFixture struct {
	executionFixture
	planKey, startKey ed25519.PrivateKey
	delegation        *agentv1.ExecutionDelegation
	intent            *agentv1.ServiceExecutionIntent
	challenge         *agentv1.ServiceExecutionChallenge
	grant             *agentv1.ServiceExecutionStartGrant
}

func newServiceAuthorityFixture(t *testing.T) serviceAuthorityFixture {
	t.Helper()
	f := serviceAuthorityFixture{executionFixture: newExecutionFixture(t, 1), planKey: testKey(t), startKey: testKey(t)}
	delegation := &agentv1.ExecutionDelegation{
		DeploymentId: f.root.GetDeploymentId(), RootVersion: 1, Version: 1, MinimumRecoveryEpoch: 3,
		NotBefore: timestamppb.New(f.now.Add(-time.Minute)), ExpiresAt: timestamppb.New(f.now.Add(time.Hour)),
		Delegates: []*agentv1.ExecutionDelegate{
			{Key: executionTestKey(t, f.planKey), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: []string{"systemd.service.v1"}},
			{Key: executionTestKey(t, f.startKey), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, Capabilities: []string{"systemd.service.v1"}},
		},
	}
	var err error
	f.delegation, err = f.verifier.VerifyDelegation(t.Context(), f.root, executionSign(t, f.authority, delegation, f.keys...), 0, 0, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.intent = &agentv1.ServiceExecutionIntent{
		DeploymentId: f.root.GetDeploymentId(), DeviceId: uuid.NewString(), EnrollmentGeneration: uuid.NewString(),
		ActionId: uuid.NewString(), DesiredRevision: uuid.NewString(), ActorId: uuid.NewString(), ResourceSequence: 1,
		RecoveryEpoch: 3, RootVersion: 1, DelegationVersion: 1, AuthorizationVersion: 1,
		NotBefore: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(5 * time.Minute)),
		Desired: &agentv1.ServiceDesiredState{Unit: "example.service", Runtime: agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED},
	}
	digest := sha256.Sum256(executionSign(t, f.authority, f.intent, f.planKey))
	f.challenge = &agentv1.ServiceExecutionChallenge{
		DeploymentId: f.intent.GetDeploymentId(), DeviceId: f.intent.GetDeviceId(), EnrollmentGeneration: f.intent.GetEnrollmentGeneration(),
		ActionId: f.intent.GetActionId(), DesiredRevision: f.intent.GetDesiredRevision(), ResourceSequence: 1, RecoveryEpoch: 3,
		IntentSha256: digest[:], NativePlanSha256: bytes.Repeat([]byte{1}, 32), Nonce: bytes.Repeat([]byte{2}, 32),
		BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), IssuedAt: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(30 * time.Second)),
	}
	f.grant = &agentv1.ServiceExecutionStartGrant{
		Challenge: proto.CloneOf(f.challenge), ActorId: f.intent.GetActorId(), AuthorizationVersion: 1, RootVersion: 1, DelegationVersion: 1,
		NotBefore: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(30 * time.Second)),
	}
	return f
}

func TestServiceIntentRequiresCurrentScopedPlanAuthority(t *testing.T) {
	f := newServiceAuthorityFixture(t)
	for _, tc := range []struct {
		name   string
		key    ed25519.PrivateKey
		change func(*agentv1.ServiceExecutionIntent, *agentv1.ExecutionDelegation)
		at     time.Time
		valid  bool
	}{
		{name: "authorized", key: f.planKey, at: f.now, valid: true},
		{name: "start role", key: f.startKey, at: f.now},
		{name: "offline root", key: f.keys[0], at: f.now},
		{name: "TLS CA", key: f.reserved[0], at: f.now},
		{name: "expiry boundary", key: f.planKey, at: f.intent.GetExpiresAt().AsTime()},
		{name: "not yet valid", key: f.planKey, at: f.now.Add(-time.Nanosecond)},
		{name: "wrong deployment", key: f.planKey, at: f.now, change: func(i *agentv1.ServiceExecutionIntent, _ *agentv1.ExecutionDelegation) {
			i.DeploymentId = uuid.NewString()
		}},
		{name: "recovery rollback", key: f.planKey, at: f.now, change: func(i *agentv1.ServiceExecutionIntent, _ *agentv1.ExecutionDelegation) { i.RecoveryEpoch-- }},
		{name: "revoked delegation version", key: f.planKey, at: f.now, change: func(_ *agentv1.ServiceExecutionIntent, d *agentv1.ExecutionDelegation) { d.Version++ }},
		{name: "capability is exact", key: f.planKey, at: f.now, change: func(_ *agentv1.ServiceExecutionIntent, d *agentv1.ExecutionDelegation) {
			d.Delegates[0].Capabilities = []string{"systemd.service.v2"}
		}},
		{name: "intent outlives delegation", key: f.planKey, at: f.now, change: func(_ *agentv1.ServiceExecutionIntent, d *agentv1.ExecutionDelegation) {
			d.ExpiresAt = timestamppb.New(f.now.Add(time.Minute))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent, delegation := proto.CloneOf(f.intent), proto.CloneOf(f.delegation)
			if tc.change != nil {
				tc.change(intent, delegation)
			}
			// Every candidate delegation is genuinely root-authenticated.
			delegation, err := f.verifier.VerifyDelegation(t.Context(), f.root, executionSign(t, f.authority, delegation, f.keys...), 0, 0, f.now)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.verifier.VerifyServiceIntent(t.Context(), f.root, delegation, executionSign(t, f.authority, intent, tc.key), tc.at)
			if tc.valid {
				if err != nil || !proto.Equal(got, intent) {
					t.Fatalf("valid preflight rejected: %v", err)
				}
			} else if err == nil || got != nil {
				t.Fatal("unauthorized preflight accepted")
			}
		})
	}
}

func TestServiceStartBindsExactChallengeAndFreshAuthorization(t *testing.T) {
	f := newServiceAuthorityFixture(t)
	for _, tc := range []struct {
		name   string
		key    ed25519.PrivateKey
		change func(*agentv1.ServiceExecutionStartGrant)
		at     time.Time
		valid  bool
	}{
		{name: "authorized", key: f.startKey, at: f.now, valid: true},
		{name: "plan role", key: f.planKey, at: f.now},
		{name: "offline root", key: f.keys[0], at: f.now},
		{name: "expired challenge", key: f.startKey, at: f.now.Add(30 * time.Second)},
		{name: "wrong actor", key: f.startKey, at: f.now, change: func(g *agentv1.ServiceExecutionStartGrant) { g.ActorId = uuid.NewString() }},
		{name: "changed authorization", key: f.startKey, at: f.now, change: func(g *agentv1.ServiceExecutionStartGrant) { g.AuthorizationVersion++ }},
		{name: "changed root", key: f.startKey, at: f.now, change: func(g *agentv1.ServiceExecutionStartGrant) { g.RootVersion++ }},
		{name: "changed delegation", key: f.startKey, at: f.now, change: func(g *agentv1.ServiceExecutionStartGrant) { g.DelegationVersion++ }},
		{name: "native plan substitution", key: f.startKey, at: f.now, change: func(g *agentv1.ServiceExecutionStartGrant) { g.Challenge.NativePlanSha256[0] ^= 1 }},
		{name: "device substitution", key: f.startKey, at: f.now, change: func(g *agentv1.ServiceExecutionStartGrant) { g.Challenge.DeviceId = uuid.NewString() }},
		{name: "same boot process restart", key: f.startKey, at: f.now, change: func(g *agentv1.ServiceExecutionStartGrant) { g.Challenge.ExecutorIncarnation = uuid.NewString() }},
		{name: "nonce substitution", key: f.startKey, at: f.now, change: func(g *agentv1.ServiceExecutionStartGrant) { g.Challenge.Nonce[0] ^= 1 }},
		{name: "issued before challenge", key: f.startKey, at: f.now, change: func(g *agentv1.ServiceExecutionStartGrant) {
			g.NotBefore = timestamppb.New(f.now.Add(-time.Second))
			g.ExpiresAt = timestamppb.New(f.now.Add(29 * time.Second))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := proto.CloneOf(f.grant)
			if tc.change != nil {
				tc.change(grant)
			}
			got, err := f.verifier.VerifyServiceStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, grant, tc.key), f.intent, f.challenge, tc.at)
			if tc.valid {
				if err != nil || !proto.Equal(got, grant) {
					t.Fatalf("valid start rejected: %v", err)
				}
			} else if err == nil || got != nil {
				t.Fatal("unauthorized start accepted")
			}
		})
	}
	proof := executionSign(t, f.authority, f.challenge, f.startKey)
	if _, err := f.verifier.VerifyServiceStart(t.Context(), f.root, f.delegation, proof, f.intent, f.challenge, f.now); err == nil {
		t.Fatal("device challenge domain became start authority")
	}
}
