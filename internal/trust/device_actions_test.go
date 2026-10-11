package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

type deviceActionAuthorityFixture struct {
	serviceAuthorityFixture
	intent    *agentv1.DeviceActionIntent
	challenge *agentv1.DeviceActionChallenge
	grant     *agentv1.DeviceActionStartGrant
}

func newDeviceActionAuthorityFixture(t *testing.T, destructive bool) deviceActionAuthorityFixture {
	t.Helper()
	f := deviceActionAuthorityFixture{serviceAuthorityFixture: newServiceAuthorityFixture(t)}
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}}
	if destructive {
		spec.Action = &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_OFFLINE, Target: &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: uuid.NewString(), Wwn: "fixture-wwn", Serial: "fixture-serial", SizeBytes: 1 << 30}}}
	}
	capability, err := DeviceActionCapability(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.delegation.Delegates {
		d.Capabilities = []string{capability, "device.escrow-rotate.v1", "device.local-admin-rotate.v1"}
	}
	f.delegation, err = f.verifier.VerifyDelegation(t.Context(), f.root, executionSign(t, f.authority, f.delegation, f.keys...), 0, 0, f.now)
	if err != nil {
		t.Fatal(err)
	}
	specDigest, err := DeviceActionDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	f.intent = &agentv1.DeviceActionIntent{
		DeploymentId: f.root.GetDeploymentId(), DeviceId: uuid.NewString(), EnrollmentGeneration: uuid.NewString(),
		ActionId: uuid.NewString(), ActorId: uuid.NewString(), ActionSequence: 1, RecoveryEpoch: 3,
		RootVersion: 1, DelegationVersion: 1, AuthorizationVersion: 2,
		NotBefore: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(5 * time.Minute)), Spec: spec, SpecSha256: specDigest[:],
	}
	intentDigest := sha256.Sum256(executionSign(t, f.authority, f.intent, f.planKey))
	plan := &agentv1.DeviceActionPlan{Spec: proto.CloneOf(spec), ActionId: f.intent.GetActionId(), Before: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(f.now), Supported: true, RecoveryEnvironment: destructive, OffTargetJournal: destructive}}
	planDigest, err := DeviceActionDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	f.challenge = &agentv1.DeviceActionChallenge{
		DeploymentId: f.intent.GetDeploymentId(), DeviceId: f.intent.GetDeviceId(), EnrollmentGeneration: f.intent.GetEnrollmentGeneration(), ActionId: f.intent.GetActionId(),
		ActionSequence: 1, RecoveryEpoch: 3, IntentSha256: intentDigest[:], SpecSha256: bytes.Clone(specDigest[:]), NativePlanSha256: planDigest[:], NativePlan: plan,
		Nonce: bytes.Repeat([]byte{9}, 32), BootId: uuid.NewString(), ExecutorIncarnation: uuid.NewString(), IssuedAt: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(30 * time.Second)),
	}
	f.grant = &agentv1.DeviceActionStartGrant{Challenge: proto.CloneOf(f.challenge), ActorId: f.intent.GetActorId(), AuthorizationVersion: 2, RootVersion: 1, DelegationVersion: 1, NotBefore: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(30 * time.Second))}
	if destructive {
		binding := &agentv1.DeviceActionApprovalBinding{DeviceId: f.intent.GetDeviceId(), EnrollmentGeneration: f.intent.GetEnrollmentGeneration(), SpecSha256: bytes.Clone(specDigest[:]), ExpiresAt: proto.CloneOf(f.intent.GetExpiresAt())}
		f.grant.Approvals = []*agentv1.DeviceActionHumanApproval{
			{ActorId: f.intent.GetActorId(), AuthorizationVersion: 2, Binding: binding},
			{ActorId: uuid.NewString(), AuthorizationVersion: 4, Binding: proto.CloneOf(binding)},
		}
	}
	return f
}

// Bypass schema validation to test hostile signed payloads at the verifier.
func signDeviceActionUnchecked(t *testing.T, message proto.Message, domain string, key ed25519.PrivateKey) []byte {
	t.Helper()
	public := ed25519.PublicKey(key[ed25519.SeedSize:])
	id, err := KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := dsse.NewEnvelopeSigner(&edSigner{edVerifier: edVerifier{public: public, id: id}, private: key})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.SignPayload(t.Context(), domain, payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestDeviceActionIntentRequiresExactScopedAuthority(t *testing.T) {
	f := newDeviceActionAuthorityFixture(t, false)
	for _, tc := range []struct {
		name   string
		key    ed25519.PrivateKey
		change func(*agentv1.DeviceActionIntent, *agentv1.ExecutionDelegation)
		at     time.Time
		valid  bool
	}{
		{name: "valid", key: f.planKey, at: f.now, valid: true},
		{name: "start key", key: f.startKey, at: f.now},
		{name: "root key", key: f.keys[0], at: f.now},
		{name: "reserved device CA key", key: f.reserved[1], at: f.now},
		{name: "expired", key: f.planKey, at: f.intent.ExpiresAt.AsTime()},
		{name: "future", key: f.planKey, at: f.now.Add(-time.Nanosecond)},
		{name: "different deployment", key: f.planKey, at: f.now, change: func(i *agentv1.DeviceActionIntent, _ *agentv1.ExecutionDelegation) { i.DeploymentId = uuid.NewString() }},
		{name: "spec substituted", key: f.planKey, at: f.now, change: func(i *agentv1.DeviceActionIntent, _ *agentv1.ExecutionDelegation) { i.SpecSha256[0] ^= 1 }},
		{name: "epoch rollback", key: f.planKey, at: f.now, change: func(i *agentv1.DeviceActionIntent, _ *agentv1.ExecutionDelegation) { i.RecoveryEpoch-- }},
		{name: "revoked delegate", key: f.planKey, at: f.now, change: func(_ *agentv1.DeviceActionIntent, d *agentv1.ExecutionDelegation) { d.Version++ }},
		{name: "wrong capability", key: f.planKey, at: f.now, change: func(_ *agentv1.DeviceActionIntent, d *agentv1.ExecutionDelegation) {
			d.Delegates[0].Capabilities = []string{"device.lock-sessions.v2"}
		}},
		{name: "outlives delegation", key: f.planKey, at: f.now, change: func(_ *agentv1.DeviceActionIntent, d *agentv1.ExecutionDelegation) {
			d.ExpiresAt = timestamppb.New(f.now.Add(time.Minute))
		}},
		{name: "unknown fields", key: f.planKey, at: f.now, change: func(i *agentv1.DeviceActionIntent, _ *agentv1.ExecutionDelegation) {
			i.Spec.ProtoReflect().SetUnknown([]byte{0x80, 0x06, 0x01})
		}},
		{name: "missing action", key: f.planKey, at: f.now, change: func(i *agentv1.DeviceActionIntent, _ *agentv1.ExecutionDelegation) { i.Spec.Action = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent, delegation := proto.CloneOf(f.intent), proto.CloneOf(f.delegation)
			if tc.change != nil {
				tc.change(intent, delegation)
			}
			delegation, err := f.verifier.VerifyDelegation(t.Context(), f.root, executionSign(t, f.authority, delegation, f.keys...), 0, 0, f.now)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.verifier.VerifyDeviceActionIntent(t.Context(), f.root, delegation, signDeviceActionUnchecked(t, intent, DeviceActionIntentType, tc.key), tc.at)
			if tc.valid {
				if err != nil || !proto.Equal(got, intent) {
					t.Fatalf("valid intent rejected: %v", err)
				}
			} else if err == nil || got != nil {
				t.Fatal("unauthorized action intent accepted")
			}
		})
	}
}

func TestDeviceActionStartRequiresExactFreshTwoHumanBinding(t *testing.T) {
	f := newDeviceActionAuthorityFixture(t, true)
	for _, tc := range []struct {
		name   string
		change func(*agentv1.DeviceActionStartGrant)
	}{
		{name: "missing second human", change: func(g *agentv1.DeviceActionStartGrant) { g.Approvals = g.Approvals[:1] }},
		{name: "same human twice", change: func(g *agentv1.DeviceActionStartGrant) { g.Approvals[1].ActorId = g.Approvals[0].ActorId }},
		{name: "different approved target", change: func(g *agentv1.DeviceActionStartGrant) { g.Approvals[1].Binding.DeviceId = uuid.NewString() }},
		{name: "different approved generation", change: func(g *agentv1.DeviceActionStartGrant) {
			g.Approvals[1].Binding.EnrollmentGeneration = uuid.NewString()
		}},
		{name: "different approved payload", change: func(g *agentv1.DeviceActionStartGrant) { g.Approvals[1].Binding.SpecSha256[0] ^= 1 }},
		{name: "different approved expiry", change: func(g *agentv1.DeviceActionStartGrant) {
			g.Approvals[1].Binding.ExpiresAt = timestamppb.New(f.now.Add(time.Minute))
		}},
		{name: "stale actor authorization", change: func(g *agentv1.DeviceActionStartGrant) { g.Approvals[0].AuthorizationVersion++ }},
		{name: "wrong actor", change: func(g *agentv1.DeviceActionStartGrant) { g.ActorId = uuid.NewString() }},
		{name: "root changed", change: func(g *agentv1.DeviceActionStartGrant) { g.RootVersion++ }},
		{name: "delegation changed", change: func(g *agentv1.DeviceActionStartGrant) { g.DelegationVersion++ }},
		{name: "nonce replay", change: func(g *agentv1.DeviceActionStartGrant) { g.Challenge.Nonce[0] ^= 1 }},
		{name: "same boot restart", change: func(g *agentv1.DeviceActionStartGrant) { g.Challenge.ExecutorIncarnation = uuid.NewString() }},
		{name: "native plan substitution", change: func(g *agentv1.DeviceActionStartGrant) { g.Challenge.NativePlanSha256[0] ^= 1 }},
		{name: "lifetime extended", change: func(g *agentv1.DeviceActionStartGrant) { g.ExpiresAt = timestamppb.New(f.now.Add(31 * time.Second)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := proto.CloneOf(f.grant)
			tc.change(grant)
			if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, signDeviceActionUnchecked(t, grant, DeviceActionStartType, f.startKey), f.intent, f.challenge, f.now); err == nil {
				t.Fatal("invalid destructive start accepted")
			}
		})
	}
	envelope := executionSign(t, f.authority, f.grant, f.startKey)
	if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, envelope, f.intent, f.challenge, f.now); err != nil {
		t.Fatalf("valid destructive grant rejected: %v", err)
	}
	if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, envelope, f.intent, f.challenge, f.now.Add(30*time.Second)); err == nil {
		t.Fatal("expired grant accepted")
	}
	for _, key := range []ed25519.PrivateKey{f.planKey, f.keys[0], f.reserved[0]} {
		if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, f.grant, key), f.intent, f.challenge, f.now); err == nil {
			t.Fatal("wrong role accepted")
		}
	}
	if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, signDeviceActionUnchecked(t, f.grant, DeviceActionEscrowReceiptType, f.startKey), f.intent, f.challenge, f.now); err == nil {
		t.Fatal("receipt domain accepted as start authority")
	}
	challenge := proto.CloneOf(f.challenge)
	challenge.NativePlan.Before.RecoveryEnvironment = false
	digest, err := DeviceActionDigest(challenge.NativePlan)
	if err != nil {
		t.Fatal(err)
	}
	challenge.NativePlanSha256 = digest[:]
	grant := proto.CloneOf(f.grant)
	grant.Challenge = challenge
	if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, grant, f.startKey), f.intent, challenge, f.now); err == nil {
		t.Fatal("live target destructive start accepted")
	}
}

func TestDeviceActionEscrowReceiptBindsDurableCiphertextAndSlot(t *testing.T) {
	f := newDeviceActionAuthorityFixture(t, false)
	luks := uuid.NewString()
	f.intent.Spec.Action = &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{Target: &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: luks, Wwn: "fixture-wwn", Serial: "fixture-serial", SizeBytes: 1 << 30}, EscrowKeyId: string(bytes.Repeat([]byte{'a'}, 64)), EscrowPublicKey: bytes.Repeat([]byte{1}, 512)}}
	escrow := &agentv1.DeviceActionEscrow{EscrowKeyId: f.intent.Spec.GetEscrowRotate().GetEscrowKeyId(), Ciphertext: []byte("ciphertext"), RecoveryKeySha256: bytes.Repeat([]byte{3}, 32), NewKeyslot: 3, LuksUuid: luks, MetadataSha256: bytes.Repeat([]byte{4}, 32), TokenId: 5}
	record := &agentv1.DeviceActionRecord{Intent: f.intent, IntentSha256: bytes.Repeat([]byte{7}, 32), StartedAt: timestamppb.New(f.now), Verification: &agentv1.DeviceActionVerification{Escrow: escrow}}
	digest, err := DeviceActionDigest(escrow)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &agentv1.DeviceActionEscrowReceipt{DeploymentId: f.intent.GetDeploymentId(), DeviceId: f.intent.GetDeviceId(), EnrollmentGeneration: f.intent.GetEnrollmentGeneration(), ActionId: f.intent.GetActionId(), IntentSha256: bytes.Clone(record.IntentSha256), EscrowSha256: digest[:], RecoveryKeySha256: bytes.Clone(escrow.RecoveryKeySha256), NewKeyslot: escrow.NewKeyslot, LuksUuid: luks, EscrowKeyId: escrow.EscrowKeyId, StoredAt: timestamppb.New(f.now), RootVersion: 1, DelegationVersion: 1}
	for _, tc := range []struct {
		name   string
		change func(*agentv1.DeviceActionEscrowReceipt)
	}{
		{name: "wrong action", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.ActionId = uuid.NewString() }},
		{name: "wrong generation", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.EnrollmentGeneration = uuid.NewString() }},
		{name: "wrong intent", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.IntentSha256[0] ^= 1 }},
		{name: "changed ciphertext", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.EscrowSha256[0] ^= 1 }},
		{name: "wrong key", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.RecoveryKeySha256[0] ^= 1 }},
		{name: "wrong slot", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.NewKeyslot++ }},
		{name: "wrong volume", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.LuksUuid = uuid.NewString() }},
		{name: "old delegation", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.DelegationVersion++ }},
		{name: "future receipt", change: func(r *agentv1.DeviceActionEscrowReceipt) { r.StoredAt = timestamppb.New(f.now.Add(time.Second)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proto.CloneOf(receipt)
			tc.change(candidate)
			if _, err := f.verifier.VerifyDeviceActionEscrowReceipt(t.Context(), f.root, f.delegation, executionSign(t, f.authority, candidate, f.startKey), record, f.now); err == nil {
				t.Fatal("unbound escrow receipt accepted")
			}
		})
	}
	if _, err := f.verifier.VerifyDeviceActionEscrowReceipt(t.Context(), f.root, f.delegation, executionSign(t, f.authority, receipt, f.startKey), record, f.now.Add(10*time.Minute)); err != nil {
		t.Fatalf("durable receipt rejected after intent expiry: %v", err)
	}
	if _, err := f.verifier.VerifyDeviceActionEscrowReceipt(t.Context(), f.root, f.delegation, executionSign(t, f.authority, receipt, f.planKey), record, f.now); err == nil {
		t.Fatal("plan role minted custody receipt")
	}
	// Lost response followed by key rollover must not strand the staged slot:
	// the new current signer attests the original durable commit timestamp.
	nextKey := testKey(t)
	next := proto.CloneOf(f.delegation)
	next.Version++
	next.NotBefore = timestamppb.New(f.now.Add(time.Minute))
	next.Delegates[1].Key = executionTestKey(t, nextKey)
	next, err = f.verifier.VerifyDelegation(t.Context(), f.root, executionSign(t, f.authority, next, f.keys...), f.delegation.GetVersion(), f.delegation.GetMinimumRecoveryEpoch(), f.now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	reissued := proto.CloneOf(receipt)
	reissued.DelegationVersion = next.GetVersion()
	if _, err := f.verifier.VerifyDeviceActionEscrowReceipt(t.Context(), f.root, next, executionSign(t, f.authority, reissued, nextKey), record, f.now.Add(2*time.Minute)); err != nil {
		t.Fatalf("current signer rejected historical custody commit: %v", err)
	}
	if _, err := f.verifier.VerifyDeviceActionEscrowReceipt(t.Context(), f.root, next, executionSign(t, f.authority, reissued, f.startKey), record, f.now.Add(2*time.Minute)); err == nil {
		t.Fatal("retired signer accepted after rollover")
	}
}

func TestDeviceActionStartRejectsUnqualifiedRootPreflight(t *testing.T) {
	f := newDeviceActionAuthorityFixture(t, true)
	for _, tc := range []struct {
		name   string
		change func(*agentv1.DeviceActionChallenge)
	}{
		{name: "unsupported", change: func(c *agentv1.DeviceActionChallenge) { c.NativePlan.Before.Supported = false }},
		{name: "journal on erased target", change: func(c *agentv1.DeviceActionChallenge) { c.NativePlan.Before.OffTargetJournal = false }},
		{name: "wrong plan action", change: func(c *agentv1.DeviceActionChallenge) { c.NativePlan.ActionId = uuid.NewString() }},
		{name: "wrong plan target", change: func(c *agentv1.DeviceActionChallenge) {
			c.NativePlan.Spec.GetCryptoErase().Target.LuksUuid = uuid.NewString()
		}},
		{name: "wrong challenge generation", change: func(c *agentv1.DeviceActionChallenge) { c.EnrollmentGeneration = uuid.NewString() }},
		{name: "wrong challenge spec digest", change: func(c *agentv1.DeviceActionChallenge) { c.SpecSha256[0] ^= 1 }},
		{name: "sequence replay", change: func(c *agentv1.DeviceActionChallenge) { c.ActionSequence++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			challenge := proto.CloneOf(f.challenge)
			tc.change(challenge)
			digest, err := DeviceActionDigest(challenge.NativePlan)
			if err != nil {
				t.Fatal(err)
			}
			challenge.NativePlanSha256 = digest[:]
			grant := proto.CloneOf(f.grant)
			grant.Challenge = challenge
			if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, grant, f.startKey), f.intent, challenge, f.now); err == nil {
				t.Fatal("freshly signed but unqualified preflight accepted")
			}
		})
	}
}

func TestDeviceActionCapabilityIsClosedAndActionSpecific(t *testing.T) {
	for _, tc := range []struct {
		spec *agentv1.DeviceActionSpec
		want string
	}{
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{}}}, "device.escrow-rotate.v1"},
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Tpm2Bind{Tpm2Bind: &agentv1.TPM2BindAction{}}}, "device.tpm2-bind.v1"},
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LockSessions{LockSessions: &agentv1.LockSessionsAction{}}}, "device.lock-sessions.v1"},
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{}}}, "device.release-lock.v1"},
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Quarantine{Quarantine: &agentv1.QuarantineAction{}}}, "device.quarantine.v1"},
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseQuarantine{ReleaseQuarantine: &agentv1.ReleaseQuarantineAction{}}}, "device.release-quarantine.v1"},
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{}}}, "device.crypto-erase.v1"},
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Sanitize{Sanitize: &agentv1.SanitizeAction{}}}, "device.sanitize.v1"},
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}}, "device.restart.v1"},
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Shutdown{Shutdown: &agentv1.ShutdownAction{}}}, "device.shutdown.v1"},
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}}, "device.refresh-inventory.v1"},
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_LocalAdminPasswordRotate{LocalAdminPasswordRotate: &agentv1.LocalAdminPasswordRotateAction{}}}, "device.local-admin-rotate.v1"},
		{&agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_PatchNow{PatchNow: &agentv1.PatchNowAction{}}}, "device.patch-now.v1"},
	} {
		got, err := DeviceActionCapability(tc.spec)
		if err != nil || got != tc.want {
			t.Fatalf("capability = %q, %v; want %q", got, err, tc.want)
		}
	}
	for _, spec := range []*agentv1.DeviceActionSpec{nil, {}} {
		if _, err := DeviceActionCapability(spec); err == nil {
			t.Fatal("missing action acquired a capability")
		}
	}
}

func TestDeviceActionEscrowStartBindsSelectedUnoccupiedSlot(t *testing.T) {
	f := newDeviceActionAuthorityFixture(t, false)
	target := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: uuid.NewString(), Wwn: "fixture-wwn", Serial: "fixture-serial", SizeBytes: 1 << 30}
	f.intent.Spec.Action = &agentv1.DeviceActionSpec_EscrowRotate{EscrowRotate: &agentv1.EscrowRotateAction{
		Target: target, EscrowKeyId: string(bytes.Repeat([]byte{'a'}, 64)), EscrowPublicKey: bytes.Repeat([]byte{1}, 512),
	}}
	specDigest, err := DeviceActionDigest(f.intent.Spec)
	if err != nil {
		t.Fatal(err)
	}
	f.intent.SpecSha256 = specDigest[:]
	intentDigest := sha256.Sum256(executionSign(t, f.authority, f.intent, f.planKey))
	f.challenge.IntentSha256 = intentDigest[:]
	f.challenge.SpecSha256 = bytes.Clone(specDigest[:])
	f.challenge.NativePlan.Spec = proto.CloneOf(f.intent.Spec)
	f.challenge.NativePlan.Before.Target = proto.CloneOf(target)
	f.challenge.NativePlan.Before.OccupiedKeyslots = []uint32{0, 1}
	f.challenge.NativePlan.RecoveryBinding = &agentv1.RecoveryKeyBinding{
		DeviceId: f.intent.GetDeviceId(), EnrollmentGeneration: f.intent.GetEnrollmentGeneration(),
		ActionId: f.intent.GetActionId(), LuksUuid: target.GetLuksUuid(), NewKeyslot: 7,
	}
	digest, err := DeviceActionDigest(f.challenge.NativePlan)
	if err != nil {
		t.Fatal(err)
	}
	f.challenge.NativePlanSha256 = digest[:]
	f.grant.Challenge = proto.CloneOf(f.challenge)
	envelope := executionSign(t, f.authority, f.grant, f.startKey)
	if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, envelope, f.intent, f.challenge, f.now); err != nil {
		t.Fatalf("nonzero selected free slot rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		slot   uint32
		rehash bool
	}{
		{name: "occupied slot freshly signed", slot: 1, rehash: true},
		{name: "slot substituted without plan hash", slot: 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			challenge := proto.CloneOf(f.challenge)
			challenge.NativePlan.RecoveryBinding.NewKeyslot = tc.slot
			if tc.rehash {
				updatedDigest, err := DeviceActionDigest(challenge.NativePlan)
				if err != nil {
					t.Fatal(err)
				}
				challenge.NativePlanSha256 = updatedDigest[:]
			}
			grant := proto.CloneOf(f.grant)
			grant.Challenge = challenge
			if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, executionSign(t, f.authority, grant, f.startKey), f.intent, challenge, f.now); err == nil {
				t.Fatal("unbound or occupied recovery slot accepted")
			}
		})
	}
	substituted := proto.CloneOf(f.challenge)
	substituted.NativePlan.RecoveryBinding.NewKeyslot = 8
	changedDigest, err := DeviceActionDigest(substituted.NativePlan)
	if err != nil {
		t.Fatal(err)
	}
	substituted.NativePlanSha256 = changedDigest[:]
	if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, envelope, f.intent, substituted, f.now); err == nil {
		t.Fatal("original grant accepted different selected slot and plan hash")
	}
}

func TestReleaseLockRequiresIndependentSignedCapability(t *testing.T) {
	f := newDeviceActionAuthorityFixture(t, false)
	f.intent.Spec = &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_ReleaseLock{ReleaseLock: &agentv1.ReleaseLockAction{LockActionId: uuid.NewString()}}}
	specDigest, err := DeviceActionDigest(f.intent.GetSpec())
	if err != nil {
		t.Fatal(err)
	}
	f.intent.SpecSha256 = specDigest[:]
	envelope := executionSign(t, f.authority, f.intent, f.planKey)
	if _, err := f.verifier.VerifyDeviceActionIntent(t.Context(), f.root, f.delegation, envelope, f.now); err == nil {
		t.Fatal("lock-only signer authorized release")
	}
	for _, delegate := range f.delegation.Delegates {
		delegate.Capabilities = []string{"device.release-lock.v1"}
	}
	if _, err := f.verifier.VerifyDeviceActionIntent(t.Context(), f.root, f.delegation, envelope, f.now); err != nil {
		t.Fatal(err)
	}
	intentDigest := sha256.Sum256(envelope)
	f.challenge.IntentSha256 = intentDigest[:]
	f.challenge.SpecSha256 = specDigest[:]
	f.challenge.NativePlan.Spec = proto.CloneOf(f.intent.GetSpec())
	planDigest, err := DeviceActionDigest(f.challenge.GetNativePlan())
	if err != nil {
		t.Fatal(err)
	}
	f.challenge.NativePlanSha256 = planDigest[:]
	f.grant.Challenge = proto.CloneOf(f.challenge)
	start := executionSign(t, f.authority, f.grant, f.startKey)
	if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, start, f.intent, f.challenge, f.now); err != nil {
		t.Fatal(err)
	}
	f.delegation.Delegates[1].Capabilities = []string{"device.lock-sessions.v1"}
	if _, err := f.verifier.VerifyDeviceActionStart(t.Context(), f.root, f.delegation, start, f.intent, f.challenge, f.now); err == nil {
		t.Fatal("lock-only start signer authorized release")
	}
}
