//go:build integration

package device

import (
	"crypto/ed25519"
	"testing"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
)

func TestDeviceActionLiveRootAggregateRequiresVolatileExactProof(t *testing.T) {
	f := newDeviceActionFixture(t)
	targets := []*agentv1.StorageTarget{fixtureStorageTarget(uuid.NewString()), fixtureStorageTarget(uuid.NewString())}
	targets[1].SizeBytes = 2 << 30
	f.observeStorageTargets(t, targets...)
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER, Targets: targets}}}
	request := f.request(spec)
	f.approval(t, request)
	action := f.create(t, request)
	work := f.work(t)
	start, challenge := f.startRequest(t, work)
	omitted := proto.CloneOf(challenge)
	omitted.NativePlan.CryptoEraseTargets = omitted.NativePlan.CryptoEraseTargets[:1]
	var err error
	omitted.NativePlanSha256, err = core.ActionDigest(omitted.NativePlan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(&devicev1.AuthorizeDeviceActionStartRequest{SessionEpoch: 1, ActionId: action.GetActionId(), ChallengeProof: f.sign(t, omitted)})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("incomplete aggregate grant: %v", err)
	}
	if _, err := f.svc.AuthorizeDeviceActionStart(f.deviceCtx(), connect.NewRequest(start)); err != nil {
		t.Fatal(err)
	}
	before, err := f.svc.GetDeviceAction(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceActionRequest{ActionId: action.GetActionId()}))
	if err != nil || before.Msg.GetAction().GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_OUTCOME_UNKNOWN {
		t.Fatalf("missing terminal proof not unknown: %v", err)
	}
	verification := &agentv1.DeviceActionVerification{Verified: true, After: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.Now(), Supported: true}}
	for _, target := range challenge.GetNativePlan().GetCryptoEraseTargets() {
		verification.CryptoEraseResults = append(verification.CryptoEraseResults, &agentv1.CryptoEraseTargetResult{Target: target.GetTarget(), HeaderBytes: target.GetLuksHeaderBytes(), NativeLuksErase: true, RawZeroVerified: true, MetadataAbsent: true, Evidence: "isolated signed server-proof fixture; no native effects"})
	}
	result := f.result(t, work, 1, agentv1.DeviceActionState_DEVICE_ACTION_STATE_SUCCEEDED, verification)
	attestation := new(agentv1.DeviceActionAttestation)
	if err := f.svc.Authority.Verify(t.Context(), result.GetAttestationEnvelope(), attestation, 1, ed25519.PublicKey(f.key[ed25519.SeedSize:])); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("nonvolatile success admitted: %v", err)
	}
	attestation.Status.VolatileResult = true
	attestation.Status.ReportOnly = true
	attestation.Status.Before = challenge.GetNativePlan().GetBefore()
	attestation.Status.Verification.CryptoEraseResults[1].RawZeroVerified = false
	result.AttestationEnvelope = f.sign(t, attestation)
	if _, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("incomplete raw proof admitted: %v", err)
	}
	attestation.Status.Verification.CryptoEraseResults[1].RawZeroVerified = true
	result.AttestationEnvelope = f.sign(t, attestation)
	response, err := f.svc.ReportDeviceActionResult(f.deviceCtx(), connect.NewRequest(result))
	if err != nil || !response.Msg.GetClosed() {
		t.Fatalf("exact aggregate volatile proof: %v", err)
	}
	for _, target := range targets {
		state, err := f.svc.GetDeviceEncryption(f.ownerCtx, connect.NewRequest(&adminv1.GetDeviceEncryptionRequest{DeviceId: f.deviceID, LuksUuid: target.GetLuksUuid()}))
		if err != nil {
			t.Fatal(err)
		}
		if state.Msg.GetObservation().GetEncrypted() || state.Msg.GetObservation().GetTarget().GetLuksUuid() != target.GetLuksUuid() {
			t.Fatal("aggregate result not projected onto selected encrypted volume")
		}
	}
}
