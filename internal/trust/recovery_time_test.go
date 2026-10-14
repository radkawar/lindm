// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
)

type recoveryTimeFixture struct {
	serviceAuthorityFixture
	request   *recoveryv1.GetRecoveryTimeRequest
	response  *recoveryv1.GetRecoveryTimeResponse
	statement *agentv1.RecoveryTimeStatement
}

func newRecoveryTimeFixture(t *testing.T) recoveryTimeFixture {
	t.Helper()
	f := recoveryTimeFixture{serviceAuthorityFixture: newServiceAuthorityFixture(t)}
	for _, delegate := range f.delegation.Delegates {
		delegate.Capabilities = []string{"device.sanitize.v1"}
	}
	envelope := executionSign(t, f.authority, f.delegation, f.keys...)
	rootDigest, err := ExecutionRootDigest(f.root)
	if err != nil {
		t.Fatal(err)
	}
	delegationDigest := sha256.Sum256(envelope)
	f.request = &recoveryv1.GetRecoveryTimeRequest{
		Nonce: bytes.Repeat([]byte{7}, 32), BootId: uuid.NewString(),
		RootVersion: f.root.GetVersion(), RootSha256: rootDigest[:],
		DelegationVersion: f.delegation.GetVersion(), DelegationSha256: delegationDigest[:],
		MinimumRecoveryEpoch: f.delegation.GetMinimumRecoveryEpoch(),
	}
	requestDigest, err := DeviceActionDigest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	f.statement = &agentv1.RecoveryTimeStatement{
		DeploymentId: f.root.GetDeploymentId(), RequestSha256: requestDigest[:],
		ServerTime: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(30 * time.Second)),
		RootVersion: f.root.GetVersion(), DelegationVersion: f.delegation.GetVersion(),
	}
	f.response = &recoveryv1.GetRecoveryTimeResponse{
		ServerTime: timestamppb.New(f.now), TimeEnvelope: executionSign(t, f.authority, f.statement, f.startKey),
		TrustUpdate: &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: envelope},
	}
	return f
}

func TestRecoveryTimeBindsExactRequestAndCurrentAuthority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *recoveryTimeFixture)
	}{
		{name: "wrong nonce", change: func(_ *testing.T, f *recoveryTimeFixture) { f.request.Nonce[0] ^= 1 }},
		{name: "replayed response in another boot", change: func(_ *testing.T, f *recoveryTimeFixture) { f.request.BootId = uuid.NewString() }},
		{name: "wrong request digest", change: func(t *testing.T, f *recoveryTimeFixture) {
			f.statement.RequestSha256[0] ^= 1
			f.response.TimeEnvelope = executionSign(t, f.authority, f.statement, f.startKey)
		}},
		{name: "unsigned hint substitution", change: func(_ *testing.T, f *recoveryTimeFixture) {
			f.response.ServerTime = timestamppb.New(f.now.Add(time.Nanosecond))
		}},
		{name: "wrong deployment", change: func(t *testing.T, f *recoveryTimeFixture) {
			f.statement.DeploymentId = uuid.NewString()
			f.response.TimeEnvelope = executionSign(t, f.authority, f.statement, f.startKey)
		}},
		{name: "wrong root version", change: func(t *testing.T, f *recoveryTimeFixture) {
			f.statement.RootVersion++
			f.response.TimeEnvelope = executionSign(t, f.authority, f.statement, f.startKey)
		}},
		{name: "wrong delegation version", change: func(t *testing.T, f *recoveryTimeFixture) {
			f.statement.DelegationVersion++
			f.response.TimeEnvelope = executionSign(t, f.authority, f.statement, f.startKey)
		}},
		{name: "plan role", change: func(t *testing.T, f *recoveryTimeFixture) {
			f.response.TimeEnvelope = executionSign(t, f.authority, f.statement, f.planKey)
		}},
		{name: "root key", change: func(t *testing.T, f *recoveryTimeFixture) {
			f.response.TimeEnvelope = executionSign(t, f.authority, f.statement, f.keys[0])
		}},
		{name: "transport key", change: func(t *testing.T, f *recoveryTimeFixture) {
			f.response.TimeEnvelope = executionSign(t, f.authority, f.statement, f.reserved[0])
		}},
		{name: "wrong domain with valid signature", change: func(t *testing.T, f *recoveryTimeFixture) {
			f.response.TimeEnvelope = signDeviceActionUnchecked(t, f.statement, RecoveryCheckpointReceiptType, f.startKey)
		}},
		{name: "protected root digest", change: func(_ *testing.T, f *recoveryTimeFixture) { f.request.RootSha256[0] ^= 1 }},
		{name: "root rollback", change: func(_ *testing.T, f *recoveryTimeFixture) { f.request.RootVersion++ }},
		{name: "delegation rollback", change: func(_ *testing.T, f *recoveryTimeFixture) { f.request.DelegationVersion++ }},
		{name: "epoch rollback", change: func(_ *testing.T, f *recoveryTimeFixture) { f.request.MinimumRecoveryEpoch++ }},
		{name: "unchanged envelope substitution", change: func(_ *testing.T, f *recoveryTimeFixture) {
			f.response.TrustUpdate.DelegationEnvelope = append(f.response.TrustUpdate.DelegationEnvelope, '\n')
		}},
		{name: "missing explicit delegation", change: func(_ *testing.T, f *recoveryTimeFixture) { f.response.TrustUpdate = nil }},
		{name: "oversized envelope", change: func(_ *testing.T, f *recoveryTimeFixture) { f.response.TimeEnvelope = make([]byte, 16385) }},
		{name: "unknown request field", change: func(_ *testing.T, f *recoveryTimeFixture) {
			f.request.ProtoReflect().SetUnknown([]byte{0x80, 0x01, 0x01})
		}},
		{name: "wrong capability", change: func(t *testing.T, f *recoveryTimeFixture) {
			f.delegation.Version++
			f.delegation.Delegates[1].Capabilities = []string{"device.sanitize.v2"}
			f.response.TrustUpdate.DelegationEnvelope = executionSign(t, f.authority, f.delegation, f.keys...)
			f.statement.DelegationVersion++
			f.response.TimeEnvelope = executionSign(t, f.authority, f.statement, f.startKey)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRecoveryTimeFixture(t)
			tc.change(t, &f)
			statement, root, delegation, err := f.verifier.VerifyRecoveryTime(t.Context(), f.root, f.response, f.request, f.now, 0)
			if err == nil || statement != nil || root != nil || delegation != nil {
				t.Fatalf("unbound time returned: statement=%v root=%v delegation=%v err=%v", statement, root, delegation, err)
			}
		})
	}
}

func TestRecoveryTimeValidityAndRoundTripBoundaries(t *testing.T) {
	f := newRecoveryTimeFixture(t)
	for _, tc := range []struct {
		name    string
		elapsed time.Duration
		minimum time.Time
		valid   bool
	}{
		{name: "zero RTT and exact minimum", minimum: f.now, valid: true},
		{name: "one nanosecond RTT", minimum: f.now, elapsed: time.Nanosecond, valid: true},
		{name: "last instant before expiry", minimum: f.now, elapsed: 30*time.Second - time.Nanosecond, valid: true},
		{name: "exact thirty second expiry", minimum: f.now, elapsed: 30 * time.Second},
		{name: "RTT over maximum", minimum: f.now, elapsed: 30*time.Second + time.Nanosecond},
		{name: "negative RTT", minimum: f.now, elapsed: -time.Nanosecond},
		{name: "below protected minimum", minimum: f.now.Add(time.Nanosecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statement, root, delegation, err := f.verifier.VerifyRecoveryTime(t.Context(), f.root, f.response, f.request, tc.minimum, tc.elapsed)
			if tc.valid {
				if err != nil || !proto.Equal(statement, f.statement) || !proto.Equal(root, f.root) || !proto.Equal(delegation, f.delegation) {
					t.Fatalf("valid bounded time rejected: %v", err)
				}
			} else if err == nil || statement != nil || root != nil || delegation != nil {
				t.Fatal("invalid interval authenticated")
			}
		})
	}
	for _, duration := range []time.Duration{0, -time.Nanosecond, 30*time.Second + time.Nanosecond} {
		statement := proto.CloneOf(f.statement)
		statement.ExpiresAt = timestamppb.New(f.now.Add(duration))
		response := proto.CloneOf(f.response)
		response.TimeEnvelope = signDeviceActionUnchecked(t, statement, RecoveryTimeType, f.startKey)
		if _, _, _, err := f.verifier.VerifyRecoveryTime(t.Context(), f.root, response, f.request, f.now, 0); err == nil {
			t.Fatalf("invalid signed duration accepted: %s", duration)
		}
	}
}

func TestRecoveryTimeEntireIntervalFitsRootAndDelegation(t *testing.T) {
	for _, boundary := range []string{"root not before", "root expiry", "delegation not before", "delegation expiry", "statement expiry"} {
		t.Run(boundary, func(t *testing.T) {
			f := newRecoveryTimeFixture(t)
			begin, end := f.now, f.now.Add(5*time.Second)
			switch boundary {
			case "root not before":
				f.root.NotBefore = timestamppb.New(begin)
				f.delegation.NotBefore = timestamppb.New(begin)
			case "root expiry":
				f.root.ExpiresAt = timestamppb.New(end)
				f.delegation.ExpiresAt = timestamppb.New(end)
				f.statement.ExpiresAt = timestamppb.New(end)
			case "delegation not before":
				f.delegation.NotBefore = timestamppb.New(begin)
			case "delegation expiry":
				f.delegation.ExpiresAt = timestamppb.New(end)
				f.statement.ExpiresAt = timestamppb.New(end)
			case "statement expiry":
				f.statement.ExpiresAt = timestamppb.New(end)
			}
			rootDigest, err := ExecutionRootDigest(f.root)
			if err != nil {
				t.Fatal(err)
			}
			f.request.RootSha256 = rootDigest[:]
			f.response.TrustUpdate.DelegationEnvelope = executionSign(t, f.authority, f.delegation, f.keys...)
			delegationDigest := sha256.Sum256(f.response.TrustUpdate.DelegationEnvelope)
			f.request.DelegationSha256 = delegationDigest[:]
			requestDigest, err := DeviceActionDigest(f.request)
			if err != nil {
				t.Fatal(err)
			}
			f.statement.RequestSha256 = requestDigest[:]
			f.response.TimeEnvelope = executionSign(t, f.authority, f.statement, f.startKey)
			if _, _, _, err := f.verifier.VerifyRecoveryTime(t.Context(), f.root, f.response, f.request, f.now, 5*time.Second-time.Nanosecond); err != nil {
				t.Fatalf("interval inside validity rejected: %v", err)
			}
			if boundary == "root not before" || boundary == "delegation not before" {
				f.statement.ServerTime = timestamppb.New(f.now.Add(-time.Nanosecond))
				f.statement.ExpiresAt = timestamppb.New(end)
				f.response.ServerTime = f.statement.ServerTime
				f.response.TimeEnvelope = executionSign(t, f.authority, f.statement, f.startKey)
			} else {
				// Candidate remains valid; only the conservative upper bound expires.
				begin = f.now.Add(5 * time.Second)
			}
			if _, _, _, err := f.verifier.VerifyRecoveryTime(t.Context(), f.root, f.response, f.request, f.now.Add(-time.Second), begin.Sub(f.now)); err == nil {
				t.Fatal("interval crossed an authority validity boundary")
			}
		})
	}
}

func TestRecoveryTimeAuthenticatesConsecutiveRootUpdates(t *testing.T) {
	f := newRecoveryTimeFixture(t)
	nextKey := testKey(t)
	next := proto.CloneOf(f.root)
	next.Version++
	next.Keys = []*agentv1.ExecutionKey{executionTestKey(t, nextKey)}
	transition := &agentv1.ExecutionRootTransition{
		PreviousQuorumEnvelope: executionSign(t, f.authority, next, f.keys...),
		NextQuorumEnvelope:     executionSign(t, f.authority, next, nextKey),
	}
	f.delegation.RootVersion = next.GetVersion()
	f.delegation.Version++
	f.delegation.MinimumRecoveryEpoch++
	f.response.TrustUpdate.RootTransitions = []*agentv1.ExecutionRootTransition{transition}
	f.response.TrustUpdate.DelegationEnvelope = executionSign(t, f.authority, f.delegation, nextKey)
	f.statement.RootVersion = next.GetVersion()
	f.statement.DelegationVersion = f.delegation.GetVersion()
	f.response.TimeEnvelope = executionSign(t, f.authority, f.statement, f.startKey)
	if _, root, delegation, err := f.verifier.VerifyRecoveryTime(t.Context(), f.root, f.response, f.request, f.now, time.Second); err != nil || !proto.Equal(root, next) || !proto.Equal(delegation, f.delegation) {
		t.Fatalf("authenticated trust transition rejected: %v", err)
	}
	transition.PreviousQuorumEnvelope = transition.NextQuorumEnvelope
	if _, _, _, err := f.verifier.VerifyRecoveryTime(t.Context(), f.root, f.response, f.request, f.now, 0); err == nil {
		t.Fatal("self-signed replacement root established time")
	}
}
