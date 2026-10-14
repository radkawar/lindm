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
)

// localAdminFixture re-signs the shared fixture for one local-admin rotation
// whose root plan binds the exact device, generation, action and account.
func localAdminFixture(t *testing.T) (deviceActionAuthorityFixture, *agentv1.LocalAdminPasswordBinding) {
	t.Helper()
	f := newDeviceActionAuthorityFixture(t, false)
	f.intent.Spec = &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LocalAdminPasswordRotate{LocalAdminPasswordRotate: &agentv1.LocalAdminPasswordRotateAction{AccountName: "lapsadmin", EscrowKeyId: string(bytes.Repeat([]byte{'b'}, 64)), EscrowPublicKey: bytes.Repeat([]byte{1}, 512)}}}
	specDigest, err := DeviceActionDigest(f.intent.Spec)
	if err != nil {
		t.Fatal(err)
	}
	f.intent.SpecSha256 = specDigest[:]
	binding := &agentv1.LocalAdminPasswordBinding{DeviceId: f.intent.GetDeviceId(), EnrollmentGeneration: f.intent.GetEnrollmentGeneration(), ActionId: f.intent.GetActionId(), AccountName: "lapsadmin", AccountUid: 1001}
	f.challenge.NativePlan.Spec = proto.CloneOf(f.intent.Spec)
	f.challenge.NativePlan.LocalAdminBinding = proto.CloneOf(binding)
	f.challenge.SpecSha256 = bytes.Clone(specDigest[:])
	resignLocalAdminChallenge(t, &f)
	return f, binding
}

func resignLocalAdminChallenge(t *testing.T, f *deviceActionAuthorityFixture) {
	t.Helper()
	intentDigest := sha256.Sum256(executionSign(t, f.authority, f.intent, f.planKey))
	planDigest, err := DeviceActionDigest(f.challenge.NativePlan)
	if err != nil {
		t.Fatal(err)
	}
	f.challenge.IntentSha256, f.challenge.NativePlanSha256 = intentDigest[:], planDigest[:]
	f.grant.Challenge = proto.CloneOf(f.challenge)
}

func TestDeviceActionStartBindsLocalAdminAccount(t *testing.T) {
	f, _ := localAdminFixture(t)
	if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, f.grant, f.startKey), f.intent, f.challenge, f.now); err != nil {
		t.Fatalf("exact local-admin plan rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.LocalAdminPasswordBinding) *agentv1.LocalAdminPasswordBinding
	}{
		{name: "missing", change: func(*agentv1.LocalAdminPasswordBinding) *agentv1.LocalAdminPasswordBinding { return nil }},
		{name: "other account", change: func(b *agentv1.LocalAdminPasswordBinding) *agentv1.LocalAdminPasswordBinding {
			b.AccountName = "operator"
			return b
		}},
		{name: "root uid", change: func(b *agentv1.LocalAdminPasswordBinding) *agentv1.LocalAdminPasswordBinding {
			b.AccountUid = 0
			return b
		}},
		{name: "other action", change: func(b *agentv1.LocalAdminPasswordBinding) *agentv1.LocalAdminPasswordBinding {
			b.ActionId = uuid.NewString()
			return b
		}},
		{name: "other device", change: func(b *agentv1.LocalAdminPasswordBinding) *agentv1.LocalAdminPasswordBinding {
			b.DeviceId = uuid.NewString()
			return b
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := localAdminFixture(t)
			g.challenge.NativePlan.LocalAdminBinding = tc.change(g.challenge.NativePlan.LocalAdminBinding)
			resignLocalAdminChallenge(t, &g)
			if _, err := g.verifier.VerifyDeviceActionStart(t.Context(), g.root, g.delegation, executionSign(t, g.authority, g.grant, g.startKey), g.intent, g.challenge, g.now); err == nil {
				t.Fatal("unbound local-admin plan accepted")
			}
		})
	}
	// A local-admin binding cannot ride along on another action kind.
	other := newDeviceActionAuthorityFixture(t, false)
	other.challenge.NativePlan.LocalAdminBinding = &agentv1.LocalAdminPasswordBinding{DeviceId: other.intent.GetDeviceId(), EnrollmentGeneration: other.intent.GetEnrollmentGeneration(), ActionId: other.intent.GetActionId(), AccountName: "lapsadmin", AccountUid: 1001}
	resignLocalAdminChallenge(t, &other)
	if _, err := other.verifier.VerifyDeviceActionStart(t.Context(), other.root, other.delegation, executionSign(t, other.authority, other.grant, other.startKey), other.intent, other.challenge, other.now); err == nil {
		t.Fatal("local-admin binding accepted on a lock action")
	}
}

func TestDeviceActionEscrowReceiptBindsLocalAdminKind(t *testing.T) {
	f, binding := localAdminFixture(t)
	escrow := &agentv1.DeviceActionEscrow{EscrowKeyId: f.intent.Spec.GetLocalAdminPasswordRotate().GetEscrowKeyId(), Ciphertext: []byte("ciphertext"), RecoveryKeySha256: bytes.Repeat([]byte{3}, 32), LocalAdmin: proto.CloneOf(binding)}
	record := &agentv1.DeviceActionRecord{Intent: f.intent, IntentSha256: bytes.Repeat([]byte{7}, 32), StartedAt: timestamppb.New(f.now), Verification: &agentv1.DeviceActionVerification{Escrow: escrow}}
	digest, err := DeviceActionDigest(escrow)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &agentv1.DeviceActionEscrowReceipt{DeploymentId: f.intent.GetDeploymentId(), DeviceId: f.intent.GetDeviceId(), EnrollmentGeneration: f.intent.GetEnrollmentGeneration(), ActionId: f.intent.GetActionId(), IntentSha256: bytes.Clone(record.IntentSha256), EscrowSha256: digest[:], RecoveryKeySha256: bytes.Clone(escrow.RecoveryKeySha256), EscrowKeyId: escrow.EscrowKeyId, StoredAt: timestamppb.New(f.now), RootVersion: 1, DelegationVersion: 1, LocalAdmin: proto.CloneOf(binding)}
	if _, err := f.verifier.VerifyDeviceActionEscrowReceipt(t.Context(), f.root, f.delegation, executionSign(t, f.authority, receipt, f.startKey), record, f.now.Add(10*time.Minute)); err != nil {
		t.Fatalf("durable local-admin receipt rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.DeviceActionEscrowReceipt)
	}{
		{name: "recovery kind", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.LocalAdmin, r.LuksUuid = nil, uuid.NewString() }},
		{name: "other account", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.LocalAdmin.AccountName = "operator" }},
		{name: "other uid", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.LocalAdmin.AccountUid++ }},
		{name: "changed ciphertext", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.EscrowSha256[0] ^= 1 }},
		{name: "wrong password digest", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.RecoveryKeySha256[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proto.CloneOf(receipt)
			tc.change(candidate)
			if _, err := f.verifier.VerifyDeviceActionEscrowReceipt(t.Context(), f.root, f.delegation, signDeviceActionUnchecked(t, candidate, DeviceActionEscrowReceiptType, f.startKey), record, f.now); err == nil {
				t.Fatal("unbound local-admin receipt accepted")
			}
		})
	}
	// A consistently signed escrow staged for another action is not this action's.
	rebound := proto.CloneOf(record)
	rebound.Verification.Escrow.LocalAdmin.ActionId = uuid.NewString()
	reboundDigest, err := DeviceActionDigest(rebound.Verification.Escrow)
	if err != nil {
		t.Fatal(err)
	}
	reboundReceipt := proto.CloneOf(receipt)
	reboundReceipt.EscrowSha256, reboundReceipt.LocalAdmin = reboundDigest[:], proto.CloneOf(rebound.Verification.Escrow.LocalAdmin)
	if _, err := f.verifier.VerifyDeviceActionEscrowReceipt(t.Context(), f.root, f.delegation, executionSign(t, f.authority, reboundReceipt, f.startKey), rebound, f.now); err == nil {
		t.Fatal("rebound local-admin escrow accepted")
	}
	if _, err := f.verifier.VerifyDeviceActionEscrowReceipt(t.Context(), f.root, f.delegation, executionSign(t, f.authority, receipt, f.planKey), record, f.now); err == nil {
		t.Fatal("plan role minted local-admin receipt")
	}
}
