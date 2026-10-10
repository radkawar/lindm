//go:build linux

package recovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	recoveryv1 "lindm/gen/lindm/recovery/v1"
	"lindm/internal/trust"
)

func recoveryProofFixture(t *testing.T) (*trust.Authority, ed25519.PrivateKey, *agentv1.DeviceActionRecoveryCredential, time.Time) {
	t.Helper()
	return recoveryProofFixtureAt(t, time.Now())
}

func recoveryProofFixtureAt(t *testing.T, now time.Time) (*trust.Authority, ed25519.PrivateKey, *agentv1.DeviceActionRecoveryCredential, time.Time) {
	t.Helper()
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	image := bytes.Repeat([]byte{3}, 32)
	target := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, Wwn: "fixture-wwn", Serial: "fixture-serial", SizeBytes: 4096}
	mediaDigest, err := trust.DeviceActionDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	media := mediaDigest[:]
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{Target: target, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE, Recovery: &agentv1.RecoveryBootSpec{ImageSha256: image, MediaSha256: media, BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI}}}}
	specDigest, err := trust.DeviceActionDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	intent := &agentv1.DeviceActionIntent{DeploymentId: uuid.NewString(), DeviceId: uuid.NewString(), EnrollmentGeneration: uuid.NewString(), ActionId: uuid.NewString(), ActorId: uuid.NewString(), ActionSequence: 1, RootVersion: 1, DelegationVersion: 1, AuthorizationVersion: 1, NotBefore: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Minute)), Spec: spec, SpecSha256: specDigest[:]}
	plan := &agentv1.DeviceActionPlan{Spec: spec, ActionId: intent.GetActionId(), Before: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(now), Supported: true, Target: spec.GetSanitize().GetTarget()}}
	planDigest, err := trust.DeviceActionDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	intentDigest := bytes.Repeat([]byte{6}, 32)
	challenge := &agentv1.DeviceActionChallenge{DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), ActionId: intent.GetActionId(), ActionSequence: 1, IntentSha256: intentDigest, SpecSha256: specDigest[:], NativePlanSha256: planDigest[:], Nonce: bytes.Repeat([]byte{7}, 32), BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)), NativePlan: plan}
	canonical, err := trust.RecoveryPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	handoff := &agentv1.DeviceActionRecoveryHandoff{Intent: intent, IntentSha256: intentDigest, Challenge: challenge, NativePlanSha256: canonical[:], RecoveryImageSha256: image, MediaSha256: media, RecoveryPublicKey: public, OriginalBootId: challenge.GetBootId(), ExpiresAt: intent.GetExpiresAt(), Custody: agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET}
	credential := &agentv1.DeviceActionRecoveryCredential{CredentialId: uuid.NewString(), Handoff: handoff, RootVersion: 1, DelegationVersion: 1, IssuedAt: timestamppb.New(now), ExpiresAt: intent.GetExpiresAt()}
	return authority, key, credential, now
}

func TestRecoveryProofBindsEndpointCredentialAndPayload(t *testing.T) {
	authority, key, credential, now := recoveryProofFixture(t)
	envelope := []byte("exact server credential envelope")
	payload := &recoveryv1.AuthorizeRecoveryStartRequest{Challenge: proto.CloneOf(credential.GetHandoff().GetChallenge()), RecoveryImageSha256: credential.GetHandoff().GetRecoveryImageSha256()}
	proof, err := requestProof(t.Context(), authority, key, credential, envelope, uuid.NewString(), uuid.NewString(), agentv1.RecoveryOperation_RECOVERY_OPERATION_AUTHORIZE_START, payload, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.VerifyRecoveryRequestProof(t.Context(), proof, envelope, credential, agentv1.RecoveryOperation_RECOVERY_OPERATION_AUTHORIZE_START, payload, now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"endpoint", "credential", "payload", "expiry", "ordinary_key"} {
		t.Run(name, func(t *testing.T) {
			candidate := proto.CloneOf(payload)
			issued := proof
			credentialBytes := envelope
			operation := agentv1.RecoveryOperation_RECOVERY_OPERATION_AUTHORIZE_START
			at := now
			switch name {
			case "endpoint":
				operation = agentv1.RecoveryOperation_RECOVERY_OPERATION_CHECKPOINT
			case "credential":
				credentialBytes = []byte("different credential bytes")
			case "payload":
				candidate.Challenge.NativePlan.Spec.GetSanitize().Target.Serial = "different media"
			case "expiry":
				at = now.Add(30 * time.Second)
			case "ordinary_key":
				_, other, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				issued, err = requestProof(t.Context(), authority, other, credential, envelope, uuid.NewString(), uuid.NewString(), operation, candidate, now)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := authority.VerifyRecoveryRequestProof(t.Context(), issued, credentialBytes, credential, operation, candidate, at); err == nil {
				t.Fatal("scope substitution accepted")
			}
		})
	}
}

func TestRecoveryProofRejectsOriginalBootAndIncarnation(t *testing.T) {
	authority, key, credential, now := recoveryProofFixture(t)
	for _, oldBoot := range []bool{false, true} {
		boot, incarnation := uuid.NewString(), uuid.NewString()
		if oldBoot {
			boot = credential.GetHandoff().GetOriginalBootId()
		} else {
			incarnation = credential.GetHandoff().GetChallenge().GetExecutorIncarnation()
		}
		payload := new(recoveryv1.AcquireRecoveryWorkRequest)
		envelope := []byte("retained credential bytes")
		proof, err := requestProof(t.Context(), authority, key, credential, envelope, boot, incarnation, agentv1.RecoveryOperation_RECOVERY_OPERATION_ACQUIRE_WORK, payload, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authority.VerifyRecoveryRequestProof(t.Context(), proof, envelope, credential, agentv1.RecoveryOperation_RECOVERY_OPERATION_ACQUIRE_WORK, payload, now); err == nil {
			t.Fatal("original boot/incarnation crossed handoff")
		}
	}
}
