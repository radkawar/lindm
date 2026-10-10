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
	recoveryv1 "lindm/gen/lindm/recovery/v1"
)

type recoveryAuthorityFixture struct {
	deviceActionAuthorityFixture
	recoveryKey ed25519.PrivateKey
	handoff     *agentv1.DeviceActionRecoveryHandoff
	credential  *agentv1.DeviceActionRecoveryCredential
	boot        *agentv1.DeviceActionRecoveryBootGrant
}

func newRecoveryAuthorityFixture(t *testing.T) recoveryAuthorityFixture {
	t.Helper()
	f := recoveryAuthorityFixture{deviceActionAuthorityFixture: newDeviceActionAuthorityFixture(t, true), recoveryKey: testKey(t)}
	for _, delegate := range f.delegation.Delegates {
		delegate.Capabilities = []string{"device.sanitize.v1"}
	}
	var err error
	f.delegation, err = f.verifier.VerifyDelegation(t.Context(), f.root, executionSign(t, f.authority, f.delegation, f.keys...), 0, 0, f.now)
	if err != nil {
		t.Fatal(err)
	}
	target := &agentv1.StorageTarget{Serial: "recovery-media-one", SizeBytes: 1 << 30}
	media, err := DeviceActionDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	f.intent.Spec.Action = &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{
		Target: target, Method: agentv1.SanitizeMethod_SANITIZE_METHOD_OVERWRITE,
		Recovery: &agentv1.RecoveryBootSpec{ImageSha256: bytes.Repeat([]byte{5}, 32), BootMode: agentv1.RecoveryBootMode_RECOVERY_BOOT_MODE_UKI, MediaSha256: media[:]},
	}}
	specDigest, err := DeviceActionDigest(f.intent.Spec)
	if err != nil {
		t.Fatal(err)
	}
	f.intent.SpecSha256 = specDigest[:]
	intentDigest := sha256.Sum256(executionSign(t, f.authority, f.intent, f.planKey))
	f.challenge.IntentSha256, f.challenge.SpecSha256 = intentDigest[:], bytes.Clone(specDigest[:])
	f.challenge.NativePlan.Spec = proto.CloneOf(f.intent.Spec)
	f.challenge.NativePlan.Before = &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(f.now), Supported: true, Target: proto.CloneOf(target)}
	planDigest, err := DeviceActionDigest(f.challenge.NativePlan)
	if err != nil {
		t.Fatal(err)
	}
	f.challenge.NativePlanSha256 = planDigest[:]
	f.grant.Challenge = proto.CloneOf(f.challenge)
	for _, approval := range f.grant.Approvals {
		approval.Binding.SpecSha256 = bytes.Clone(specDigest[:])
	}
	canonical, err := RecoveryPlanDigest(f.challenge.NativePlan)
	if err != nil {
		t.Fatal(err)
	}
	f.handoff = &agentv1.DeviceActionRecoveryHandoff{
		Intent: proto.CloneOf(f.intent), NativePlanSha256: canonical[:], RecoveryImageSha256: bytes.Repeat([]byte{5}, 32), MediaSha256: media[:],
		RecoveryPublicKey: bytes.Clone(f.recoveryKey[ed25519.SeedSize:]), OriginalBootId: f.challenge.GetBootId(), ExpiresAt: proto.CloneOf(f.intent.ExpiresAt),
		Custody: agentv1.RecoveryCustody_RECOVERY_CUSTODY_OFF_TARGET, IntentSha256: intentDigest[:], Challenge: proto.CloneOf(f.challenge),
	}
	handoffDigest, err := DeviceActionDigest(f.handoff)
	if err != nil {
		t.Fatal(err)
	}
	f.boot = &agentv1.DeviceActionRecoveryBootGrant{Grant: proto.CloneOf(f.grant), HandoffSha256: handoffDigest[:]}
	f.credential = &agentv1.DeviceActionRecoveryCredential{CredentialId: uuid.NewString(), Handoff: proto.CloneOf(f.handoff), RootVersion: 1, DelegationVersion: 1, IssuedAt: timestamppb.New(f.now), ExpiresAt: proto.CloneOf(f.intent.ExpiresAt)}
	return f
}

func (f recoveryAuthorityFixture) recoveryGrant(t *testing.T) (*agentv1.DeviceActionChallenge, *agentv1.DeviceActionStartGrant) {
	t.Helper()
	challenge := proto.CloneOf(f.challenge)
	challenge.BootId, challenge.ExecutorIncarnation = uuid.NewString(), uuid.NewString()
	challenge.Nonce = bytes.Repeat([]byte{8}, 32)
	challenge.IssuedAt, challenge.ExpiresAt = timestamppb.New(f.now.Add(time.Minute)), timestamppb.New(f.now.Add(90*time.Second))
	challenge.NativePlan.Before.ObservedAt = timestamppb.New(f.now.Add(time.Minute))
	challenge.NativePlan.Before.RecoveryEnvironment, challenge.NativePlan.Before.OffTargetJournal = true, true
	digest, err := DeviceActionDigest(challenge.NativePlan)
	if err != nil {
		t.Fatal(err)
	}
	challenge.NativePlanSha256 = digest[:]
	grant := proto.CloneOf(f.grant)
	grant.Challenge = proto.CloneOf(challenge)
	grant.NotBefore, grant.ExpiresAt = proto.CloneOf(challenge.IssuedAt), proto.CloneOf(challenge.ExpiresAt)
	return challenge, grant
}

func TestRecoveryBootAuthorityCannotBecomeEraseAuthority(t *testing.T) {
	f := newRecoveryAuthorityFixture(t)
	bootEnvelope := executionSign(t, f.authority, f.boot, f.startKey)
	if _, err := f.verifier.VerifyDeviceActionRecoveryBoot(t.Context(), f.root, f.delegation, bootEnvelope, f.handoff, f.now); err != nil {
		t.Fatalf("valid boot grant rejected: %v", err)
	}
	if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, bootEnvelope, f.intent, f.challenge, f.now); err == nil {
		t.Fatal("BOOT domain accepted by ordinary execution")
	}
	if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, f.grant, f.startKey), f.intent, f.challenge, f.now); err == nil {
		t.Fatal("original boot granted destructive recovery effect")
	}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.DeviceActionRecoveryBootGrant)
	}{
		{name: "handoff substitution", change: func(b *agentv1.DeviceActionRecoveryBootGrant) { b.HandoffSha256[0] ^= 1 }},
		{name: "one approver", change: func(b *agentv1.DeviceActionRecoveryBootGrant) { b.Grant.Approvals = b.Grant.Approvals[:1] }},
		{name: "same human", change: func(b *agentv1.DeviceActionRecoveryBootGrant) {
			b.Grant.Approvals[1].ActorId = b.Grant.Approvals[0].ActorId
		}},
		{name: "changed incarnation", change: func(b *agentv1.DeviceActionRecoveryBootGrant) {
			b.Grant.Challenge.ExecutorIncarnation = uuid.NewString()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proto.CloneOf(f.boot)
			tc.change(candidate)
			if _, err := f.verifier.VerifyDeviceActionRecoveryBoot(t.Context(), f.root, f.delegation, signDeviceActionUnchecked(t, candidate, DeviceActionRecoveryBootType, f.startKey), f.handoff, f.now); err == nil {
				t.Fatal("unbound BOOT grant accepted")
			}
		})
	}
	if _, err := f.verifier.VerifyDeviceActionRecoveryBoot(t.Context(), f.root, f.delegation, bootEnvelope, f.handoff, f.now.Add(30*time.Second)); err == nil {
		t.Fatal("expired BOOT grant accepted")
	}
	if _, err := f.verifier.VerifyDeviceActionRecoveryBoot(t.Context(), f.root, f.delegation, executionSign(t, f.authority, f.boot, f.planKey), f.handoff, f.now); err == nil {
		t.Fatal("plan role authorized BOOT")
	}
}

func TestRecoveryEraseRequiresFreshBootAndFrozenPlan(t *testing.T) {
	f := newRecoveryAuthorityFixture(t)
	challenge, grant := f.recoveryGrant(t)
	at := f.now.Add(time.Minute)
	if _, err := f.verifier.VerifyRecoveryStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, grant, f.startKey), f.intent, challenge, f.credential, at); err != nil {
		t.Fatalf("valid recovery grant rejected: %v", err)
	}
	if _, err := f.verifier.VerifyRecoveryStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, f.boot, f.startKey), f.intent, challenge, f.credential, at); err == nil {
		t.Fatal("BOOT signature became recovery erase")
	}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.DeviceActionChallenge)
	}{
		{name: "original boot", change: func(c *agentv1.DeviceActionChallenge) { c.BootId = f.handoff.OriginalBootId }},
		{name: "original incarnation", change: func(c *agentv1.DeviceActionChallenge) {
			c.ExecutorIncarnation = f.handoff.Challenge.ExecutorIncarnation
		}},
		{name: "different media", change: func(c *agentv1.DeviceActionChallenge) { c.NativePlan.Before.Target.Serial = "other-device" }},
		{name: "missing recovery environment", change: func(c *agentv1.DeviceActionChallenge) { c.NativePlan.Before.RecoveryEnvironment = false }},
		{name: "journal on target", change: func(c *agentv1.DeviceActionChallenge) { c.NativePlan.Before.OffTargetJournal = false }},
		{name: "intent replay", change: func(c *agentv1.DeviceActionChallenge) { c.IntentSha256[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proto.CloneOf(challenge)
			tc.change(candidate)
			digest, err := DeviceActionDigest(candidate.NativePlan)
			if err != nil {
				t.Fatal(err)
			}
			candidate.NativePlanSha256 = digest[:]
			fresh := proto.CloneOf(grant)
			fresh.Challenge = proto.CloneOf(candidate)
			if _, err := f.verifier.VerifyRecoveryStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, fresh, f.startKey), f.intent, candidate, f.credential, at); err == nil {
				t.Fatal("unsafe recovery grant accepted")
			}
		})
	}
}

func TestRecoveryCredentialAndRequestArePurposeBound(t *testing.T) {
	f := newRecoveryAuthorityFixture(t)
	envelope := executionSign(t, f.authority, f.credential, f.startKey)
	credential, err := f.verifier.VerifyDeviceActionRecoveryCredential(t.Context(), f.root, f.delegation, envelope, f.handoff, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.verifier.VerifyDeviceActionRecoveryCredential(t.Context(), f.root, f.delegation, executionSign(t, f.authority, f.credential, f.planKey), f.handoff, f.now); err == nil {
		t.Fatal("plan role minted recovery credential")
	}
	changedHandoff := proto.CloneOf(f.handoff)
	changedHandoff.RecoveryPublicKey = bytes.Clone(testKey(t)[ed25519.SeedSize:])
	if _, err := f.verifier.VerifyDeviceActionRecoveryCredential(t.Context(), f.root, f.delegation, envelope, changedHandoff, f.now); err == nil {
		t.Fatal("substituted one-action key accepted")
	}
	if _, err := f.verifier.VerifyDeviceActionRecoveryCredential(t.Context(), f.root, f.delegation, envelope, f.handoff, f.credential.ExpiresAt.AsTime()); err == nil {
		t.Fatal("expired recovery credential accepted for new authority")
	}
	payload := &recoveryv1.AcquireRecoveryWorkRequest{}
	payloadDigest, err := DeviceActionDigest(payload)
	if err != nil {
		t.Fatal(err)
	}
	credentialDigest := sha256.Sum256(envelope)
	proof := &agentv1.RecoveryRequestProof{CredentialId: credential.CredentialId, CredentialSha256: credentialDigest[:], RequestId: uuid.NewString(), BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), Nonce: bytes.Repeat([]byte{1}, 32), Operation: agentv1.RecoveryOperation_RECOVERY_OPERATION_ACQUIRE_WORK, PayloadSha256: payloadDigest[:], IssuedAt: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(30 * time.Second))}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.RecoveryRequestProof)
		valid  bool
	}{
		{name: "valid", valid: true},
		{name: "cross endpoint", change: func(p *agentv1.RecoveryRequestProof) {
			p.Operation = agentv1.RecoveryOperation_RECOVERY_OPERATION_AUTHORIZE_START
		}},
		{name: "credential substitution", change: func(p *agentv1.RecoveryRequestProof) { p.CredentialSha256[0] ^= 1 }},
		{name: "payload substitution", change: func(p *agentv1.RecoveryRequestProof) { p.PayloadSha256[0] ^= 1 }},
		{name: "original boot", change: func(p *agentv1.RecoveryRequestProof) { p.BootId = f.handoff.OriginalBootId }},
		{name: "long-lived proof", change: func(p *agentv1.RecoveryRequestProof) { p.ExpiresAt = timestamppb.New(f.now.Add(time.Minute)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proto.CloneOf(proof)
			if tc.change != nil {
				tc.change(candidate)
			}
			_, err := f.authority.VerifyRecoveryRequestProof(t.Context(), signDeviceActionUnchecked(t, candidate, RecoveryRequestProofType, f.recoveryKey), envelope, credential, agentv1.RecoveryOperation_RECOVERY_OPERATION_ACQUIRE_WORK, payload, f.now)
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid && err == nil {
				t.Fatal("unbound recovery request accepted")
			}
		})
	}
	if _, err := f.authority.VerifyRecoveryRequestProof(t.Context(), executionSign(t, f.authority, proof, f.recoveryKey), envelope, credential, agentv1.RecoveryOperation_RECOVERY_OPERATION_ACQUIRE_WORK, payload, f.now.Add(30*time.Second)); err == nil {
		t.Fatal("expired request proof accepted")
	}
}

func TestRecoveryCheckpointReceiptBindsConsumedEffect(t *testing.T) {
	f := newRecoveryAuthorityFixture(t)
	checkpoint := &agentv1.RecoveryCheckpoint{CredentialId: f.credential.CredentialId, ActionId: f.intent.ActionId, BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), Sequence: 2, Phase: agentv1.RecoveryPhase_RECOVERY_PHASE_EFFECT_COMMITTED, PreviousSha256: bytes.Repeat([]byte{1}, 32), At: timestamppb.New(f.now), GrantSha256: bytes.Repeat([]byte{2}, 32)}
	digest, err := DeviceActionDigest(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &agentv1.RecoveryCheckpointReceipt{CredentialId: checkpoint.CredentialId, ActionId: checkpoint.ActionId, Sequence: checkpoint.Sequence, CheckpointSha256: digest[:], StoredAt: timestamppb.New(f.now), RootVersion: 1, DelegationVersion: 1}
	envelope := executionSign(t, f.authority, receipt, f.startKey)
	if _, err := f.verifier.VerifyRecoveryCheckpointReceipt(t.Context(), f.root, f.delegation, envelope, checkpoint, f.now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*agentv1.RecoveryCheckpoint){
		func(c *agentv1.RecoveryCheckpoint) { c.GrantSha256[0] ^= 1 },
		func(c *agentv1.RecoveryCheckpoint) { c.BootId = uuid.NewString() },
		func(c *agentv1.RecoveryCheckpoint) { c.Sequence++ },
	} {
		candidate := proto.CloneOf(checkpoint)
		change(candidate)
		if _, err := f.verifier.VerifyRecoveryCheckpointReceipt(t.Context(), f.root, f.delegation, envelope, candidate, f.now); err == nil {
			t.Fatal("checkpoint receipt authorized another effect consumption")
		}
	}
	if _, err := f.verifier.VerifyRecoveryCheckpointReceipt(t.Context(), f.root, f.delegation, executionSign(t, f.authority, receipt, f.planKey), checkpoint, f.now); err == nil {
		t.Fatal("plan role minted checkpoint receipt")
	}
}

func TestRecoveryHandoffAuthenticatesOriginalDeviceAndExactIntent(t *testing.T) {
	f := newRecoveryAuthorityFixture(t)
	certificate := newServiceAttestationFixture(t)
	var err error
	certificate.binding.DeploymentID, err = uuid.Parse(f.intent.GetDeploymentId())
	if err != nil {
		t.Fatal(err)
	}
	certificate.binding.DeviceID, err = uuid.Parse(f.intent.GetDeviceId())
	if err != nil {
		t.Fatal(err)
	}
	certificate.binding.EnrollmentGeneration, err = uuid.Parse(f.intent.GetEnrollmentGeneration())
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := certificate.certificate(t, certificate.key.Public(), nil)
	intentDigest := sha256.Sum256(executionSign(t, f.authority, f.intent, f.planKey))
	envelope := executionSign(t, f.authority, f.handoff, certificate.key)
	if _, err := f.authority.VerifyDeviceActionRecoveryHandoff(t.Context(), envelope, certificatePEM, certificate.ca, f.intent, intentDigest, f.now, 0); err != nil {
		t.Fatalf("valid original-device handoff rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.DeviceActionRecoveryHandoff)
	}{
		{name: "media substitution", change: func(h *agentv1.DeviceActionRecoveryHandoff) { h.MediaSha256[0] ^= 1 }},
		{name: "image substitution", change: func(h *agentv1.DeviceActionRecoveryHandoff) { h.RecoveryImageSha256[0] ^= 1 }},
		{name: "different original boot", change: func(h *agentv1.DeviceActionRecoveryHandoff) { h.OriginalBootId = uuid.NewString() }},
		{name: "native plan substitution", change: func(h *agentv1.DeviceActionRecoveryHandoff) { h.NativePlanSha256[0] ^= 1 }},
		{name: "intent envelope substitution", change: func(h *agentv1.DeviceActionRecoveryHandoff) { h.IntentSha256[0] ^= 1 }},
		{name: "unknown authority fields", change: func(h *agentv1.DeviceActionRecoveryHandoff) { h.ProtoReflect().SetUnknown([]byte{0x80, 0x06, 0x01}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proto.CloneOf(f.handoff)
			tc.change(candidate)
			if _, err := f.authority.VerifyDeviceActionRecoveryHandoff(t.Context(), signDeviceActionUnchecked(t, candidate, DeviceActionRecoveryHandoffType, certificate.key), certificatePEM, certificate.ca, f.intent, intentDigest, f.now, 0); err == nil {
				t.Fatal("unbound original-device handoff accepted")
			}
		})
	}
	if _, err := f.authority.VerifyDeviceActionRecoveryHandoff(t.Context(), executionSign(t, f.authority, f.handoff, f.recoveryKey), certificatePEM, certificate.ca, f.intent, intentDigest, f.now, 0); err == nil {
		t.Fatal("one-action key impersonated original device")
	}
	if _, err := f.authority.VerifyDeviceActionRecoveryHandoff(t.Context(), envelope, certificatePEM, certificate.ca, f.intent, intentDigest, f.now.Add(30*time.Second), 0); err == nil {
		t.Fatal("expired original-boot challenge accepted")
	}
}
