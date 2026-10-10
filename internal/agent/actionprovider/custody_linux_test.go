//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/escrow"
)

// This uses the production native planner and production RSA/AES custody path;
// only native block operations use the deterministic state machine fixture.
func TestPlannedNonzeroRecoverySlotSurvivesServerCustodyRoundTrip(t *testing.T) {
	fixture := newLUKSFixture(t)
	private, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := escrow.New(private, bytes.Repeat([]byte{0x53}, 32))
	if err != nil {
		t.Fatal(err)
	}
	spec := proto.CloneOf(fixture.plan.Spec)
	spec.GetEscrowRotate().EscrowPublicKey = custody.PublicKey()
	spec.GetEscrowRotate().EscrowKeyId = custody.KeyID()
	plan, err := fixture.p.Plan(context.Background(), spec, fixture.plan.Before)
	if err != nil {
		t.Fatal(err)
	}
	if plan.GetRecoveryBinding().GetNewKeyslot() != 2 {
		t.Fatal("planner did not freeze the actual free nonzero slot")
	}
	plan.ActionId = fixtureAction
	plan.RecoveryBinding.DeviceId = fixture.plan.RecoveryBinding.DeviceId
	plan.RecoveryBinding.EnrollmentGeneration = fixture.plan.RecoveryBinding.EnrollmentGeneration
	plan.RecoveryBinding.ActionId = fixtureAction
	frozen, err := proto.MarshalOptions{Deterministic: true}.Marshal(plan.RecoveryBinding)
	if err != nil {
		t.Fatal(err)
	}
	fixture.p.seal = func(_ context.Context, binding *agentv1.RecoveryKeyBinding, spec *agentv1.DeviceActionSpec, key []byte) ([]byte, error) {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(binding)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(encoded, frozen) {
			t.Error("Apply mutated the signed custody binding")
		}
		return escrow.SealForServer(spec.GetEscrowRotate().GetEscrowPublicKey(), encoded, key)
	}
	stage, err := fixture.p.Apply(context.Background(), plan, []byte("owner-recovery"), fixture.gate)
	if err != nil {
		t.Fatal(err)
	}
	record, err := custody.OpenAndSeal(frozen, stage.GetEscrow().GetCiphertext())
	if err != nil {
		t.Fatalf("server rejected honest nonzero-slot action: %v", err)
	}
	if !bytes.Equal(record.SecretSHA256, stage.GetEscrow().GetRecoveryKeySha256()) {
		t.Fatal("stored recovery differs from tested replacement")
	}
	wrong := proto.CloneOf(plan.RecoveryBinding)
	wrong.NewKeyslot = 0
	encodedWrong, err := proto.MarshalOptions{Deterministic: true}.Marshal(wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.OpenAndSeal(encodedWrong, stage.GetEscrow().GetCiphertext()); err == nil {
		t.Fatal("occupied old-slot binding authenticated new recovery")
	}
}

func TestApplyRefusesMutatedFrozenSlotBeforeAuthorityConsumption(t *testing.T) {
	fixture := newLUKSFixture(t)
	fixture.plan.RecoveryBinding.NewKeyslot = 3
	_, err := fixture.p.Apply(context.Background(), fixture.plan, []byte("owner-recovery"), fixture.gate)
	if err == nil || fixture.gates != 0 || fixture.keys["2"] != nil || fixture.keys["3"] != nil {
		t.Fatalf("mutated planned slot crossed effect gate: %v", err)
	}
}
