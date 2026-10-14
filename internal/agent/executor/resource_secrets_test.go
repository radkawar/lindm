// SPDX-License-Identifier: Apache-2.0

//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
	"lindm/internal/secretseal"
)

var deliveredHash = []byte("$6$lindmsalt$" + strings.Repeat("Q", 86))

// secretNative is an account-shaped effect harness. It uses only the
// executor-supplied accessor and records each plaintext use it was given.
type secretNative struct {
	mu        sync.Mutex
	svc       *Service
	boot      string
	secrets   secretAccessor
	uses      [][]byte
	plans     int
	effects   int
	openError error
}

func (n *secretNative) Close() error { return nil }

func (n *secretNative) use(ctx context.Context, desired *resourcev1.ResourceDesiredState) error {
	material, err := n.secrets(ctx, desired.GetLocalUser().GetPassword().GetHashed().GetHash())
	if err != nil {
		n.openError = err
		return err
	}
	defer secretseal.Clear(material)
	n.uses = append(n.uses, bytes.Clone(material.GetPasswordHash()))
	return nil
}

func (n *secretNative) observation(desired *resourcev1.ResourceDesiredState, exists bool) *resourcev1.ResourceObservation {
	return &resourcev1.ResourceObservation{
		Ref:      proto.CloneOf(desired.GetRef()),
		Metadata: &resourcev1.ObservationMetadata{BootId: n.boot, ExecutorIncarnation: n.svc.incarnation, ObservedAt: protoTimestamp(n.svc.now()), Backend: secretBackend(), NativeRevision: bytes.Repeat([]byte{1}, 32), ObservationStatus: resourcev1.ObservationStatus_OBSERVATION_STATUS_OK},
		Observed: &resourcev1.ResourceObservation_LocalUser{LocalUser: &resourcev1.LocalUserObservation{Name: desired.GetLocalUser().GetName(), Exists: exists, Origin: resourcev1.NSSOrigin_NSS_ORIGIN_LOCAL_FILES, LocalFileRevision: bytes.Repeat([]byte{1}, 32), IdentitySha256: bytes.Repeat([]byte{3}, 32)}},
	}
}

func secretBackend() *resourcev1.BackendSelection {
	return &resourcev1.BackendSelection{Backend: resourcev1.Backend_BACKEND_SHADOW, NativeVersion: "fixture", ProviderVersion: "fixture", Product: &resourcev1.PlatformProduct{OsId: "fixture", Product: "Fixture Linux", Version: "1", Architecture: "x86_64"}}
}

func (n *secretNative) Plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.plans++
	if err := n.use(ctx, desired); err != nil {
		return nil, err
	}
	before := n.observation(desired, false)
	desiredDigest, err := resource.DesiredDigest(desired)
	if err != nil {
		return nil, err
	}
	observationDigest, err := resource.ObservationDigest(before)
	if err != nil {
		return nil, err
	}
	claims, err := resource.Claims(desired)
	if err != nil {
		return nil, err
	}
	plan := &resourcev1.ResourcePlan{
		Ref: proto.CloneOf(desired.GetRef()), Operation: operation, Before: before, Backend: secretBackend(),
		DesiredSha256: desiredDigest[:], ObservationSha256: observationDigest[:], OwnershipRevisionSha256: digestBytes([]byte("fixture ownership")), Claims: claims,
		Safety: &resourcev1.PlanSafety{LockDomains: []resourcev1.ClaimDomain{resourcev1.ClaimDomain_CLAIM_DOMAIN_ACCOUNT}, Reversibility: resourcev1.Reversibility_REVERSIBILITY_PARTIAL, RollbackScope: resourcev1.RollbackScope_ROLLBACK_SCOPE_OWNED_DIMENSIONS, Confirmation: resourcev1.ConfirmationPolicy_CONFIRMATION_POLICY_NOT_REQUIRED},
		Plan:   &resourcev1.ResourcePlan_LocalUser{LocalUser: &resourcev1.LocalUserPlan{Desired: proto.CloneOf(desired.GetLocalUser()), Change: resourcev1.NativeObjectChange_NATIVE_OBJECT_CHANGE_CREATE, Fields: []resourcev1.UserField{resourcev1.UserField_USER_FIELD_PASSWORD}, ExpectedLocalRevision: bytes.Repeat([]byte{1}, 32), ExpectedIdentitySha256: bytes.Repeat([]byte{3}, 32)}},
	}
	return plan, resource.ValidatePlan(plan)
}

func (n *secretNative) Observe(context.Context, *resourcev1.ResourceDesiredState) (*resourcev1.ResourceObservation, error) {
	return nil, errors.New("fixture does not observe")
}

func (n *secretNative) Verify(context.Context, *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error) {
	// Drifting account plans are never verified read-only during preparation.
	return nil, errors.New("unexpected read-only verification")
}

func (n *secretNative) Apply(ctx context.Context, plan *resourcev1.ResourcePlan, authorize func(context.Context) error) (*resourcev1.ResourceVerification, error) {
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	desired := resource.PlanDesired(plan)
	if err := n.use(ctx, desired); err != nil {
		return nil, err
	}
	n.effects++
	digest, err := resource.PlanDigest(plan)
	if err != nil {
		return nil, err
	}
	receipt := &resourcev1.ProbeReceipt{ProbeId: uuid.NewString(), ObservedAt: protoTimestamp(n.svc.now()), Passed: true, EvidenceSha256: bytes.Repeat([]byte{4}, 32), Reason: "fixture"}
	verification := &resourcev1.ResourceVerification{Ref: proto.CloneOf(plan.GetRef()), DesiredSha256: bytes.Clone(plan.GetDesiredSha256()), PlanSha256: digest[:], After: n.observation(desired, true), Disposition: resourcev1.VerificationDisposition_VERIFICATION_DISPOSITION_CONVERGED,
		Checks: &resourcev1.ResourceVerification_LocalUser{LocalUser: &resourcev1.LocalUserChecks{LocalIdentityMatches: true, UidGenerationMatches: true, FieldsMatch: true, MembershipsMatch: true, PasswordPolicyMatches: true, AgingMatches: true, NssReread: receipt, Converged: true}}}
	return verification, resource.ValidateVerification(verification)
}

type secretFixture struct {
	*resourceFixture
	native    *secretNative
	recipient []byte
}

func newSecretFixture(t *testing.T) *secretFixture {
	t.Helper()
	f := &secretFixture{resourceFixture: newResourceFixture(t, false, true)}
	plan, start := delegate(t, f.planKey), delegate(t, f.startKey)
	start.Role = agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START
	plan.Capabilities = append(plan.Capabilities, "local.user.v1")
	start.Capabilities = append(start.Capabilities, "local.user.v1")
	callTrust(t, f.svc, &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: mustSign(t, f.svc.authority, delegationDocument(f.fix.deploy.String(), 1, 1, 0, f.now, plan, start), f.fix.rootKey)})
	f.native = &secretNative{svc: f.svc, boot: f.boot}
	f.openNative = func(s *Service, secrets secretAccessor) (nativeResource, error) {
		f.native.mu.Lock()
		defer f.native.mu.Unlock()
		f.native.secrets = secrets
		return f.native, nil
	}
	var err error
	f.recipient, err = secretseal.PublicKey(durable(t, f.svc).GetEncryptionPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// secretIntent returns a hashed-password intent with its exact sealed delivery.
func (f *secretFixture) secretIntent(t *testing.T, sequence uint64) (*agentv1.ResourceExecutionIntent, [][]byte) {
	t.Helper()
	intent := f.intent(t, sequence)
	ref := &resourcev1.SecretRef{SecretId: uuid.NewString(), Version: 3, Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, SubjectBindingId: uuid.NewString()}
	intent.Desired = &resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: "alice"},
		State: &resourcev1.ResourceDesiredState_LocalUser{LocalUser: &resourcev1.LocalUserDesired{Name: "alice", Presence: resourcev1.Presence_PRESENCE_PRESENT,
			Password: &resourcev1.PasswordState{State: &resourcev1.PasswordState_Hashed{Hashed: &resourcev1.HashedPasswordPolicy{Hash: ref, Algorithm: resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT}}}}},
	}
	binding := &agentv1.SecretDeliveryBinding{DeploymentId: intent.GetDeploymentId(), DeviceId: intent.GetDeviceId(), EnrollmentGeneration: intent.GetEnrollmentGeneration(), ActionId: intent.GetActionId(), Resource: proto.CloneOf(intent.GetDesired().GetRef()), Secret: proto.CloneOf(ref), RecipientKeySha256: secretseal.KeyID(f.recipient)}
	sealed := f.seal(t, f.recipient, binding)
	intent.Secrets = []*agentv1.ResourceSecretDelivery{{Binding: binding, SealedSha256: digestBytes(sealed)}}
	return intent, [][]byte{sealed}
}

func (f *secretFixture) seal(t *testing.T, recipient []byte, binding *agentv1.SecretDeliveryBinding) []byte {
	t.Helper()
	sealed, err := secretseal.Seal(recipient, binding, &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_PasswordHash{PasswordHash: bytes.Clone(deliveredHash)}})
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func (f *secretFixture) prepareSealed(t *testing.T, envelope []byte, sealed [][]byte) (*agentv1.PrepareResourceExecutionResponse, error) {
	t.Helper()
	response, err := f.svc.PrepareResourceExecution(t.Context(), connect.NewRequest(&agentv1.PrepareResourceExecutionRequest{IntentEnvelope: envelope, SealedSecrets: sealed}))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

// journalContains scans every protected state file, including SQLite WAL.
func journalContains(t *testing.T, svc *Service, needle []byte) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(svc.directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		found = found || bytes.Contains(data, needle)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestResourceSecretDeliveryAcceptedJournaledAndCleared(t *testing.T) {
	f := newSecretFixture(t)
	intent, sealed := f.secretIntent(t, 1)
	envelope := mustSign(t, f.svc.authority, intent, f.planKey)
	prepared, err := f.prepareSealed(t, envelope, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.GetStatus().GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_PREPARED || len(f.native.uses) != 1 || !bytes.Equal(f.native.uses[0], deliveredHash) {
		t.Fatal("exact delivery did not reach the provider's planning use")
	}
	record, _ := resourceRow(t, f.svc, intent.GetActionId())
	if len(record.GetSealedSecrets()) != 1 || !bytes.Equal(record.GetSealedSecrets()[0], sealed[0]) {
		t.Fatal("pending record did not retain the exact sealed bytes")
	}
	public, err := proto.Marshal(prepared)
	if err != nil || bytes.Contains(public, deliveredHash) || bytes.Contains(public, sealed[0]) {
		t.Fatal("public preparation carries secret material or ciphertext")
	}
	if journalContains(t, f.svc, deliveredHash) {
		t.Fatal("journal stores plaintext secret material")
	}
	retry, err := f.prepareSealed(t, envelope, sealed)
	if err != nil || !proto.Equal(retry, prepared) || f.native.plans != 1 {
		t.Fatalf("exact replay was not idempotent: %v", err)
	}
	// The same binding sealed again yields other ciphertext; a replay may not swap it.
	resealed := f.seal(t, f.recipient, intent.GetSecrets()[0].GetBinding())
	if _, err := f.prepareSealed(t, envelope, [][]byte{resealed}); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("replay with different ciphertext accepted: %v", err)
	}

	startResource(t, f.svc, intent.GetActionId(), f.grant(t, intent))
	terminal := awaitResourceTerminal(t, f.svc, intent.GetActionId())
	if terminal.GetState() != agentv1.ResourceExecutionState_RESOURCE_EXECUTION_STATE_SUCCEEDED || f.native.effects != 1 || len(f.native.uses) != 2 || !bytes.Equal(f.native.uses[1], deliveredHash) {
		t.Fatalf("apply did not reopen the journaled delivery: %v %v", terminal.GetState(), f.native.openError)
	}
	record, _ = resourceRow(t, f.svc, intent.GetActionId())
	if len(record.GetSealedSecrets()) != 0 {
		t.Fatal("terminal record retained sealed secrets")
	}
	public, err = proto.Marshal(terminal)
	if err != nil || bytes.Contains(public, deliveredHash) || bytes.Contains(public, sealed[0]) {
		t.Fatal("terminal status carries secret material or ciphertext")
	}
	if journalContains(t, f.svc, deliveredHash) {
		t.Fatal("journal stores plaintext secret material")
	}
	if retry, err := f.prepareSealed(t, envelope, sealed); err != nil || retry.GetStatus().GetCompletedAt() == nil {
		t.Fatalf("terminal replay with the signed delivery failed: %v", err)
	}
}

func TestResourceSecretDeliveryRefusals(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *secretFixture, *agentv1.ResourceExecutionIntent, [][]byte) [][]byte
	}{
		{"digest-mismatch", func(_ *testing.T, _ *secretFixture, _ *agentv1.ResourceExecutionIntent, sealed [][]byte) [][]byte {
			changed := bytes.Clone(sealed[0])
			changed[len(changed)-1] ^= 1
			return [][]byte{changed}
		}},
		{"count-missing", func(*testing.T, *secretFixture, *agentv1.ResourceExecutionIntent, [][]byte) [][]byte { return nil }},
		{"count-extra", func(_ *testing.T, _ *secretFixture, _ *agentv1.ResourceExecutionIntent, sealed [][]byte) [][]byte {
			return [][]byte{sealed[0], sealed[0]}
		}},
		{"manifest-missing", func(_ *testing.T, _ *secretFixture, intent *agentv1.ResourceExecutionIntent, _ [][]byte) [][]byte {
			intent.Secrets = nil
			return nil
		}},
		{"other-version", func(t *testing.T, f *secretFixture, intent *agentv1.ResourceExecutionIntent, _ [][]byte) [][]byte {
			binding := intent.GetSecrets()[0].GetBinding()
			binding.Secret.Version++
			sealed := f.seal(t, f.recipient, binding)
			intent.Secrets[0].SealedSha256 = digestBytes(sealed)
			return [][]byte{sealed}
		}},
		{"wrong-device-key", func(t *testing.T, f *secretFixture, intent *agentv1.ResourceExecutionIntent, _ [][]byte) [][]byte {
			private, err := secretseal.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			other, err := secretseal.PublicKey(private)
			if err != nil {
				t.Fatal(err)
			}
			binding := intent.GetSecrets()[0].GetBinding()
			binding.RecipientKeySha256 = secretseal.KeyID(other)
			sealed := f.seal(t, other, binding)
			intent.Secrets[0].SealedSha256 = digestBytes(sealed)
			return [][]byte{sealed}
		}},
		{"other-actions-ciphertext", func(t *testing.T, f *secretFixture, intent *agentv1.ResourceExecutionIntent, _ [][]byte) [][]byte {
			// Genuine ciphertext for another action, even with its digest signed
			// here, fails AEAD under this action's recomputed binding.
			_, foreign := f.secretIntent(t, 7)
			intent.Secrets[0].SealedSha256 = digestBytes(foreign[0])
			return foreign
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSecretFixture(t)
			intent, sealed := f.secretIntent(t, 1)
			sealed = test.mutate(t, f, intent, sealed)
			envelope := mustSign(t, f.svc.authority, intent, f.planKey)
			if _, err := f.prepareSealed(t, envelope, sealed); err == nil {
				t.Fatal("substituted delivery accepted")
			}
			if f.native.plans != 0 || len(f.native.uses) != 0 {
				t.Fatal("refused delivery reached the native provider")
			}
			if _, _, err := f.svc.store.LoadResourceAction(t.Context(), intent.GetActionId()); err == nil {
				t.Fatal("refused delivery was journaled")
			}
		})
	}
}

// Plan signers refuse manifests naming another action or resource (schema CEL).
// The executor independently recomputes the binding, so such a manifest is
// refused even if a signer's validation were bypassed.
func TestResourceSecretBindingRecomputedFromIntent(t *testing.T) {
	f := newSecretFixture(t)
	for name, mutate := range map[string]func(*agentv1.SecretDeliveryBinding){
		"other-action":   func(b *agentv1.SecretDeliveryBinding) { b.ActionId = uuid.NewString() },
		"other-resource": func(b *agentv1.SecretDeliveryBinding) { b.Resource.CanonicalKey = "bob" },
		"other-device":   func(b *agentv1.SecretDeliveryBinding) { b.DeviceId = uuid.NewString() },
		"other-subject":  func(b *agentv1.SecretDeliveryBinding) { b.Secret.SubjectBindingId = uuid.NewString() },
		"unchanged":      func(*agentv1.SecretDeliveryBinding) {},
	} {
		t.Run(name, func(t *testing.T) {
			intent, _ := f.secretIntent(t, 1)
			binding := intent.GetSecrets()[0].GetBinding()
			mutate(binding)
			sealed := f.seal(t, f.recipient, binding)
			intent.Secrets[0].SealedSha256 = digestBytes(sealed)
			f.svc.mu.Lock()
			defer f.svc.mu.Unlock()
			loaded, err := f.svc.enrolled(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			err = f.svc.verifyResourceSecrets(loaded, intent, [][]byte{sealed})
			if (err == nil) != (name == "unchanged") {
				t.Fatalf("binding verification = %v", err)
			}
		})
	}
}

func TestRetainedSecretsMustMatchSignedManifest(t *testing.T) {
	record := &agentv1.ResourceExecutionRecord{Intent: &agentv1.ResourceExecutionIntent{Secrets: []*agentv1.ResourceSecretDelivery{{SealedSha256: digestBytes([]byte("sealed"))}}}}
	if !validateRetainedSecrets(record) {
		t.Fatal("record without retained bytes rejected")
	}
	record.SealedSecrets = [][]byte{[]byte("sealed")}
	if !validateRetainedSecrets(record) {
		t.Fatal("exact retained delivery rejected")
	}
	record.SealedSecrets = [][]byte{[]byte("other")}
	if validateRetainedSecrets(record) {
		t.Fatal("retained ciphertext outside the signed manifest accepted")
	}
	record.SealedSecrets = [][]byte{[]byte("sealed")}
	record.CompletedAt = protoTimestamp(time.Unix(1, 0))
	if validateRetainedSecrets(record) {
		t.Fatal("terminal record retaining sealed bytes accepted")
	}
}
