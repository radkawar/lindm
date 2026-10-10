//go:build linux

package encryptionprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/resource"
)

const fixtureID = "11111111-1111-4111-8111-111111111111"
const fixtureUUID = "32cfd1cf-6a1c-4d7c-a792-664b3a0f4508"

func nativeFixture() *actionprovider.RootEncryptionEvidence {
	return &actionprovider.RootEncryptionEvidence{LUKSRoot: true, Target: &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: fixtureUUID, Wwn: "synthetic-wwn", Serial: "synthetic-serial", SizeBytes: 4096}, NativeSHA256: bytes.Repeat([]byte{1}, 32), MetadataSHA256: bytes.Repeat([]byte{2}, 32), Recovery: []actionprovider.RootRecoveryEvidence{{ActionID: fixtureID, Keyslot: 2, KeySHA256: bytes.Repeat([]byte{3}, 32)}}, TPMBound: true}
}
func providerFixture(t *testing.T, native *actionprovider.RootEncryptionEvidence) *Provider {
	t.Helper()
	p, err := Open(t.Context(), Config{ExecutorIncarnation: fixtureID, Platform: &resourcev1.PlatformProduct{OsId: "ubuntu", Product: "Ubuntu", Version: "24.04", Architecture: "x86_64"}, Ownership: &agentv1.ResourceOwnershipBinding{AssignmentId: fixtureID, ResourceId: fixtureID, Sources: []*agentv1.ResourceOwnershipSource{{ProfileId: fixtureID, ProfileRevision: fixtureID, ResourceId: fixtureID}}, Policy: &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_CREATE_ONLY, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RETAIN}}, Observe: func(context.Context) (*actionprovider.RootEncryptionEvidence, error) { return native, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

// This fixture models the callback's already-authenticated journal result. It
// does not claim to exercise DSSE or server escrow custody; executor tests do.
func receiptFixture(native *actionprovider.RootEncryptionEvidence) *agentv1.DeviceActionRecord {
	recovery := native.Recovery[0]
	return &agentv1.DeviceActionRecord{State: agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, Intent: &agentv1.DeviceActionIntent{ActionId: recovery.ActionID, Spec: &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{Target: proto.CloneOf(native.Target)}}}}, EscrowReceiptEnvelope: []byte("synthetic authenticated receipt identity"), EscrowConfirmedAt: timestamppb.New(time.Unix(1, 0)), ReceiptRoot: &agentv1.ExecutionRoot{}, ReceiptDelegationEnvelope: []byte("synthetic delegation"), Verification: &agentv1.DeviceActionVerification{Verified: true, After: &agentv1.DeviceActionObservation{MetadataSha256: bytes.Clone(native.MetadataSHA256)}, Escrow: &agentv1.DeviceActionEscrow{LuksUuid: native.Target.GetLuksUuid(), NewKeyslot: recovery.Keyslot, RecoveryKeySha256: bytes.Clone(recovery.KeySHA256)}}}
}
func desiredFixture() *resourcev1.ResourceDesiredState {
	return desiredState(&resourcev1.EncryptionComplianceDesired{RequireLuksRoot: true, RequireEscrow: proto.Bool(true), RequireTpm: proto.Bool(true)})
}
func TestReadOnlyComplianceRequiresAuthenticatedCurrentEscrow(t *testing.T) {
	native := nativeFixture()
	p := providerFixture(t, native)
	plan, err := p.Plan(t.Context(), desiredFixture(), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	effects := 0
	v, err := p.Apply(t.Context(), plan, func(context.Context) error { effects++; return nil })
	if !errors.Is(err, ErrNotConverged) || v.GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_DRIFTED || effects != 0 {
		t.Fatalf("unproven escrow falsely remediated: v=%v err=%v effects=%d", v, err, effects)
	}
	if v.GetEncryptionCompliance().GetEscrowRequirementMet() || len(Remediations(v)) != 1 || Remediations(v)[0].GetEscrowRotate() == nil {
		t.Fatal("missing typed escrow finding")
	}
	p.config.AuthenticatedEscrow = func(context.Context, string) (*agentv1.DeviceActionRecord, error) { return receiptFixture(native), nil }
	v, err = p.Verify(t.Context(), plan)
	if err != nil || v.GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED || !v.GetAfter().GetEncryptionCompliance().GetEscrowVerified() {
		t.Fatalf("current exact proof rejected: %v %v", v, err)
	}
	if err := resource.ValidatePlanVerification(plan, v); err != nil {
		t.Fatal(err)
	}
	if len(Remediations(v)) != 0 {
		t.Fatal("compliant evidence has remediation")
	}
}
func TestEscrowAssociationRejectsStaleOrWrongProof(t *testing.T) {
	for name, change := range map[string]func(*agentv1.DeviceActionRecord){
		"wrong root":        func(r *agentv1.DeviceActionRecord) { r.Intent.Spec.GetEscrowRotate().Target.Serial = "other" },
		"wrong uuid":        func(r *agentv1.DeviceActionRecord) { r.Verification.Escrow.LuksUuid = fixtureID },
		"wrong action":      func(r *agentv1.DeviceActionRecord) { r.Intent.ActionId = fixtureUUID },
		"wrong slot":        func(r *agentv1.DeviceActionRecord) { r.Verification.Escrow.NewKeyslot++ },
		"wrong fingerprint": func(r *agentv1.DeviceActionRecord) { r.Verification.Escrow.RecoveryKeySha256[0]++ },
		"slot replaced":     func(r *agentv1.DeviceActionRecord) { r.Verification.After.MetadataSha256[0]++ },
		"no receipt":        func(r *agentv1.DeviceActionRecord) { r.EscrowReceiptEnvelope = nil },
		"no accepted trust": func(r *agentv1.DeviceActionRecord) { r.ReceiptRoot = nil },
		"unfinished": func(r *agentv1.DeviceActionRecord) {
			r.State = agentv1.DeviceActionState_DEVICE_ACTION_STATE_AWAITING_ESCROW
		},
		"not verified": func(r *agentv1.DeviceActionRecord) { r.Verification.Verified = false },
	} {
		t.Run(name, func(t *testing.T) {
			n := nativeFixture()
			r := receiptFixture(n)
			change(r)
			if matchesEscrow(n, n.Recovery[0], r) {
				t.Fatal("stale or unrelated escrow accepted")
			}
		})
	}
	native := nativeFixture()
	p := providerFixture(t, native)
	p.config.AuthenticatedEscrow = func(context.Context, string) (*agentv1.DeviceActionRecord, error) {
		return receiptFixture(native), errors.New("invalid receipt signature")
	}
	plan, err := p.Plan(t.Context(), desiredFixture(), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	if plan.GetBefore().GetEncryptionCompliance().GetEscrowVerified() {
		t.Fatal("unauthenticated callback result accepted")
	}
}
func TestUnencryptedRootHasNoInventedActionOrSuccessfulApply(t *testing.T) {
	p := providerFixture(t, &actionprovider.RootEncryptionEvidence{NativeSHA256: bytes.Repeat([]byte{1}, 32)})
	plan, err := p.Plan(t.Context(), desiredFixture(), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.Apply(t.Context(), plan, func(context.Context) error { t.Fatal("read-only provider consumed effect authority"); return nil })
	if !errors.Is(err, ErrNotConverged) || v.GetEncryptionCompliance().GetLuksRootRequirementMet() || v.GetAfter().GetMetadata().GetReason() == "" || len(Remediations(v)) != 0 {
		t.Fatalf("unencrypted root: %v %v", v, err)
	}
}
func TestStaleTPMAndUnavailableObservationCannotConverge(t *testing.T) {
	n := nativeFixture()
	n.TPMBound = false
	p := providerFixture(t, n)
	d := desiredState(&resourcev1.EncryptionComplianceDesired{RequireLuksRoot: true, RequireTpm: proto.Bool(true)})
	plan, err := p.Plan(t.Context(), d, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.Verify(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	remediation := Remediations(v)
	if v.GetEncryptionCompliance().GetConverged() || len(remediation) != 1 || remediation[0].GetTpm2Bind() == nil || !proto.Equal(remediation[0].GetTarget(), n.Target) {
		t.Fatal("stale TPM proof accepted or wrong native remediation target")
	}
	p.config.Observe = func(context.Context) (*actionprovider.RootEncryptionEvidence, error) { return nil, os.ErrPermission }
	v, err = p.Verify(t.Context(), plan)
	if err != nil || v.GetEncryptionCompliance().GetEvidenceComplete() || v.GetDisposition() == resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED || v.GetAfter().GetMetadata().GetObservationStatus() != resourcev1.ObservationStatus_OBSERVATION_STATUS_PERMISSION_DENIED {
		t.Fatalf("unknown became compliant: %v %v", v, err)
	}
}
func TestReadOnlyReleaseAndOwnershipRefusal(t *testing.T) {
	p := providerFixture(t, nativeFixture())
	plan, err := p.Plan(t.Context(), desiredFixture(), resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE)
	if err != nil {
		t.Fatal(err)
	}
	if plan.GetEncryptionCompliance().GetChange() != resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_OBSERVE {
		t.Fatal("release invented a storage inverse")
	}
	v, err := p.Apply(t.Context(), plan, func(context.Context) error { t.Fatal("release attempted effect"); return nil })
	if err != nil || v.GetDisposition() != resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_NOT_APPLICABLE || v.GetEncryptionCompliance().GetConverged() {
		t.Fatalf("release misrepresented compliance: %v %v", v, err)
	}
	plan.OwnershipRevisionSha256[0]++
	if _, err := p.Verify(t.Context(), plan); !errors.Is(err, ErrConflict) {
		t.Fatalf("different signed ownership context accepted: %v", err)
	}
	if _, err := p.Plan(t.Context(), desiredFixture(), resourcev1.ResourceOperation_RESOURCE_OPERATION_UNSPECIFIED); err == nil {
		t.Fatal("unspecified operation accepted")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Plan(t.Context(), desiredFixture(), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE); err == nil {
		t.Fatal("closed provider accepted plan")
	}
}

func TestSerialGPTLUKSIdentityPreservesExactRemediationAndEscrowScope(t *testing.T) {
	native := nativeFixture()
	native.Target.IdentityBasis = agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS
	native.Target.Wwn = ""
	native.Target.GptDiskGuid = fixtureID
	native.Target.DiskSizeBytes = 8192
	p := providerFixture(t, native)
	plan, err := p.Plan(t.Context(), desiredFixture(), resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		t.Fatal(err)
	}
	observation := plan.GetBefore().GetEncryptionCompliance()
	if observation.GetRootIdentityBasis() != resourcev1.RootStorageIdentityBasis_ROOT_STORAGE_IDENTITY_BASIS_SERIAL_GPT_LUKS || observation.GetRootGptDiskGuid() != fixtureID || observation.GetRootDiskSizeBytes() != 8192 || observation.GetRootWwn() != "" {
		t.Fatal("durable no-WWN identity was downgraded or fabricated")
	}
	v, err := p.Verify(t.Context(), plan)
	if err != nil {
		t.Fatal(err)
	}
	remediation := Remediations(v)
	if len(remediation) != 1 || !proto.Equal(remediation[0].GetTarget(), native.Target) {
		t.Fatal("remediation lost exact existing action target basis")
	}
	record := receiptFixture(native)
	if !matchesEscrow(native, native.Recovery[0], record) {
		t.Fatal("exact durable no-WWN receipt rejected")
	}
	record.Intent.Spec.GetEscrowRotate().Target.GptDiskGuid = fixtureUUID
	if matchesEscrow(native, native.Recovery[0], record) {
		t.Fatal("other GPT disk receipt became proof")
	}
	p.config.AuthenticatedEscrow = func(context.Context, string) (*agentv1.DeviceActionRecord, error) { return receiptFixture(native), nil }
	v, err = p.Verify(t.Context(), plan)
	if err != nil || !v.GetEncryptionCompliance().GetConverged() {
		t.Fatalf("exact authenticated no-WWN proof rejected: %v %v", v, err)
	}
}

func TestUnknownAndMixedStorageIdentityBasisRefused(t *testing.T) {
	for _, basis := range []agentv1.StorageIdentityBasis{agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_UNSPECIFIED, agentv1.StorageIdentityBasis(99)} {
		target := nativeFixture().Target
		target.IdentityBasis = basis
		if err := projectRootIdentity(&resourcev1.EncryptionComplianceObservation{}, target); err == nil {
			t.Fatal("unknown native basis projected")
		}
	}
	for _, basis := range []resourcev1.RootStorageIdentityBasis{resourcev1.RootStorageIdentityBasis_ROOT_STORAGE_IDENTITY_BASIS_UNSPECIFIED, resourcev1.RootStorageIdentityBasis(99)} {
		o := &resourcev1.EncryptionComplianceObservation{RootIdentityBasis: basis, RootLuksUuid: proto.String(fixtureUUID), RootWwn: "wwn", RootSerial: "serial", RootSizeBytes: 4096}
		if _, err := rootIdentityTarget(o); err == nil {
			t.Fatal("unknown projection granted an action target")
		}
	}
	target := nativeFixture().Target
	target.GptDiskGuid = fixtureID
	target.DiskSizeBytes = 8192
	if err := projectRootIdentity(&resourcev1.EncryptionComplianceObservation{}, target); err == nil {
		t.Fatal("mixed approved identity bases accepted")
	}
}
