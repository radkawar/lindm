// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"crypto/x509"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestDeviceActionAttestationRejectsReplayAndForeignCertificates(t *testing.T) {
	f := newResourceAttestationFixture(t)
	binding := DeviceActionAttestationBinding{
		DeploymentID: f.binding.DeploymentID, DeviceID: f.binding.DeviceID, EnrollmentGeneration: f.binding.EnrollmentGeneration,
		SessionEpoch: f.binding.SessionEpoch, ActionID: f.binding.ActionID, IntentSHA256: f.binding.IntentSHA256, Nonce: f.binding.Nonce,
	}
	attestation := &agentv1.DeviceActionAttestation{
		DeploymentId: binding.DeploymentID.String(), DeviceId: binding.DeviceID.String(), EnrollmentGeneration: binding.EnrollmentGeneration.String(),
		SessionEpoch: binding.SessionEpoch, ActionRevision: 1, Nonce: bytes.Clone(binding.Nonce[:]), IssuedAt: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(30 * time.Second)),
		Status: &agentv1.DeviceActionStatus{
			ActionId: binding.ActionID.String(), IntentSha256: bytes.Clone(binding.IntentSHA256[:]), State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN,
			Failure: agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_INTERRUPTED, AcceptedAt: timestamppb.New(f.now.Add(-time.Minute)), StartedAt: timestamppb.New(f.now.Add(-time.Minute)), CompletedAt: timestamppb.New(f.now),
			Before: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(f.now.Add(-time.Minute)), Supported: true},
		},
	}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.DeviceActionAttestation, *DeviceActionAttestationBinding)
		at     time.Time
		valid  bool
	}{
		{name: "persistent unknown accepted as unknown", at: f.now, valid: true},
		{name: "expired", at: f.now.Add(30 * time.Second)},
		{name: "future", at: f.now.Add(-time.Nanosecond)},
		{name: "nonce replay", at: f.now, change: func(_ *agentv1.DeviceActionAttestation, b *DeviceActionAttestationBinding) { b.Nonce[0] ^= 1 }},
		{name: "session replay", at: f.now, change: func(_ *agentv1.DeviceActionAttestation, b *DeviceActionAttestationBinding) { b.SessionEpoch++ }},
		{name: "different action", at: f.now, change: func(a *agentv1.DeviceActionAttestation, _ *DeviceActionAttestationBinding) {
			a.Status.ActionId = uuid.NewString()
		}},
		{name: "different intent", at: f.now, change: func(a *agentv1.DeviceActionAttestation, _ *DeviceActionAttestationBinding) {
			a.Status.IntentSha256[0] ^= 1
		}},
		{name: "different generation", at: f.now, change: func(a *agentv1.DeviceActionAttestation, _ *DeviceActionAttestationBinding) {
			a.EnrollmentGeneration = uuid.NewString()
		}},
		{name: "unknown fields", at: f.now, change: func(a *agentv1.DeviceActionAttestation, _ *DeviceActionAttestationBinding) {
			a.ProtoReflect().SetUnknown([]byte{0x80, 0x06, 0x01})
		}},
		{name: "unverified success", at: f.now, change: func(a *agentv1.DeviceActionAttestation, _ *DeviceActionAttestationBinding) {
			a.Status.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED
			a.Status.Failure = agentv1.DeviceActionFailure_DEVICE_ACTION_FAILURE_NONE
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate, expected := proto.CloneOf(attestation), binding
			if tc.change != nil {
				tc.change(candidate, &expected)
			}
			envelope := signDeviceActionUnchecked(t, candidate, DeviceActionAttestationType, f.key)
			got, err := f.authority.VerifyDeviceActionAttestation(t.Context(), envelope, f.certificatePEM, f.ca, &expected, tc.at, 0)
			if tc.valid {
				if err != nil || !proto.Equal(got, candidate) {
					t.Fatalf("valid attestation rejected: %v", err)
				}
			} else if err == nil || got != nil {
				t.Fatal("unbound action attestation accepted")
			}
		})
	}
	envelope := executionSign(t, f.authority, attestation, f.key)
	for _, cert := range [][]byte{
		append(bytes.Clone(f.certificatePEM), f.certificatePEM...),
		f.certificate(t, testKey(t).Public(), nil),
		f.certificate(t, f.key.Public(), func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }),
	} {
		if _, err := f.authority.VerifyDeviceActionAttestation(t.Context(), envelope, cert, f.ca, &binding, f.now, 0); err == nil {
			t.Fatal("foreign or unsuitable certificate accepted")
		}
	}
	wrongDomain := signDeviceActionUnchecked(t, attestation, ResourceAttestationType, f.key)
	if _, err := f.authority.VerifyDeviceActionAttestation(t.Context(), wrongDomain, f.certificatePEM, f.ca, &binding, f.now, 0); err == nil {
		t.Fatal("service domain accepted as device action")
	}
}
