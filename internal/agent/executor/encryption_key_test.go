//go:build linux

package executor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/secretseal"
)

const encryptionTestGrant = "lg1_test-grant-secret-with-32-characters-minimum"

type enrolledExecutor struct {
	svc                *Service
	fix                fixture
	device, generation uuid.UUID
	cert               []byte
}

// enrollWithSession installs an identity and commits session epoch 1.
func enrollWithSession(t *testing.T, now time.Time) enrolledExecutor {
	t.Helper()
	fix := newFixture(t, now)
	boot := uuid.NewString()
	svc := openExecutor(t, now, WithBootID(func() (string, error) { return boot, nil }))
	prepare(t, svc, fix, encryptionTestGrant, false)
	device, generation := uuid.New(), uuid.New()
	cert := fix.leaf(t, publicOf(durable(t, svc).GetIdentityPrivateKey()), device, generation, now.Add(-11*24*time.Hour), now.Add(19*24*time.Hour))
	if _, err := svc.InstallEnrollment(t.Context(), connect.NewRequest(&agentv1.InstallEnrollmentRequest{DeviceId: device.String(), EnrollmentGeneration: generation.String(), CertificatePem: cert})); err != nil {
		t.Fatal(err)
	}
	pending := session(t, svc)
	if _, err := svc.CommitSession(t.Context(), connect.NewRequest(&agentv1.CommitSessionRequest{RequestId: pending.GetPending().GetRequestId(), ServerEpoch: 1})); err != nil {
		t.Fatal(err)
	}
	return enrolledExecutor{svc: svc, fix: fix, device: device, generation: generation, cert: cert}
}

// deliveryRecipient is the raw recipient public key deliveries are sealed to.
func deliveryRecipient(t *testing.T, svc *Service) []byte {
	t.Helper()
	public, err := secretseal.PublicKey(durable(t, svc).GetEncryptionPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func prepareKey(t *testing.T, svc *Service) *agentv1.PrepareEncryptionKeyResponse {
	t.Helper()
	response, err := svc.PrepareEncryptionKey(t.Context(), connect.NewRequest(&agentv1.PrepareEncryptionKeyRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg
}

func identityDigest(t *testing.T, private []byte) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicOf(private))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return sum[:]
}

func verifyAttestation(t *testing.T, e enrolledExecutor, response *agentv1.PrepareEncryptionKeyResponse) *agentv1.DeviceEncryptionKeyAttestation {
	t.Helper()
	state := durable(t, e.svc)
	claim := &agentv1.DeviceEncryptionKeyAttestation{}
	if err := e.svc.authority.Verify(t.Context(), response.GetAttestationEnvelope(), claim, 1, publicOf(state.GetIdentityPrivateKey())); err != nil {
		t.Fatalf("attestation does not verify with the installed identity key: %v", err)
	}
	if err := e.svc.authority.Verify(t.Context(), response.GetAttestationEnvelope(), &agentv1.DeviceEncryptionKeyAttestation{}, 1, publicOf(testKey(t))); err == nil {
		t.Fatal("attestation verified with another key")
	}
	public := deliveryRecipient(t, e.svc)
	certHash := sha256.Sum256(parseCert(t, state.GetCertificatePem()).Raw)
	if claim.GetDeploymentId() != e.fix.deploy.String() || claim.GetDeviceId() != e.device.String() || claim.GetEnrollmentGeneration() != e.generation.String() ||
		!bytes.Equal(claim.GetIdentityPublicKeySha256(), identityDigest(t, state.GetIdentityPrivateKey())) ||
		claim.GetKemId() != 0x20 || claim.GetKdfId() != 1 || claim.GetAeadId() != 3 || !bytes.Equal(claim.GetPublicKey(), public) ||
		!bytes.Equal(response.GetPublicKeySha256(), secretseal.KeyID(public)) || !bytes.Equal(response.GetCertificateSha256(), certHash[:]) {
		t.Fatalf("attestation does not bind the installed identity and key: %v", claim)
	}
	assertNoPrivateKey(t, e.svc, response)
	return claim
}

// assertNoPrivateKey checks a response never carries any protected scalar.
func assertNoPrivateKey(t *testing.T, svc *Service, response proto.Message) {
	t.Helper()
	state := durable(t, svc)
	encoded := mustProto(t, response)
	for _, private := range [][]byte{state.GetEncryptionPrivateKey(), state.GetPendingRenewal().GetEncryptionPrivateKey(), state.GetPriorCredential().GetEncryptionPrivateKey(), state.GetIdentityPrivateKey()[:ed25519.SeedSize]} {
		if len(private) > 0 && bytes.Contains(encoded, private) {
			t.Fatal("response exported a private key")
		}
	}
}

func testDelivery(e enrolledExecutor, recipient []byte) *agentv1.SecretDeliveryBinding {
	return &agentv1.SecretDeliveryBinding{
		DeploymentId: e.fix.deploy.String(), DeviceId: e.device.String(), EnrollmentGeneration: e.generation.String(),
		ActionId: uuid.NewString(), Resource: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: "alice"},
		Secret:             &resourcev1.SecretRef{SecretId: uuid.NewString(), Version: 2, Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_EAP_PASSWORD, SubjectBindingId: uuid.NewString()},
		RecipientKeySha256: secretseal.KeyID(recipient),
	}
}

func seal(t *testing.T, recipient []byte, binding *agentv1.SecretDeliveryBinding, plaintext string) []byte {
	t.Helper()
	sealed, err := secretseal.Seal(recipient, binding, &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_Opaque{Opaque: []byte(plaintext)}})
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func openDelivery(t *testing.T, svc *Service, binding *agentv1.SecretDeliveryBinding, sealed []byte) (*agentv1.SecretMaterial, error) {
	t.Helper()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	loaded, err := svc.enrolled(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return svc.openSecretDelivery(loaded, binding, sealed)
}

func TestEncryptionKeyFollowsIdentityLifecycle(t *testing.T) {
	now := time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)
	fix := newFixture(t, now)
	pendingSvc := openExecutor(t, now)
	bootstrap := prepare(t, pendingSvc, fix, encryptionTestGrant, false)
	if len(durable(t, pendingSvc).GetEncryptionPrivateKey()) != 32 {
		t.Fatal("bootstrap did not create the recipient key with the identity key")
	}
	assertNoPrivateKey(t, pendingSvc, bootstrap)
	created := durable(t, pendingSvc).GetEncryptionPrivateKey()
	pendingSvc = reopen(t, pendingSvc, now)
	if !bytes.Equal(durable(t, pendingSvc).GetEncryptionPrivateKey(), created) {
		t.Fatal("recipient key did not survive reopen")
	}
	if _, err := pendingSvc.PrepareEncryptionKey(t.Context(), connect.NewRequest(&agentv1.PrepareEncryptionKeyRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("uninstalled identity attested a recipient key: %v", err)
	}

	e := enrollWithSession(t, now)
	initial := durable(t, e.svc).GetEncryptionPrivateKey()
	first := prepareKey(t, e.svc)
	verifyAttestation(t, e, first)
	if first.GetAcknowledged() {
		t.Fatal("unregistered key reported acknowledged")
	}
	wrongCert := make([]byte, sha256.Size)
	for _, req := range []*agentv1.AcknowledgeEncryptionKeyRequest{
		{PublicKeySha256: first.GetPublicKeySha256(), CertificateSha256: wrongCert},
		{PublicKeySha256: wrongCert, CertificateSha256: first.GetCertificateSha256()},
	} {
		if _, err := e.svc.AcknowledgeEncryptionKey(t.Context(), connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Fatalf("stale acknowledgment accepted: %v", err)
		}
	}
	if _, err := e.svc.AcknowledgeEncryptionKey(t.Context(), connect.NewRequest(&agentv1.AcknowledgeEncryptionKeyRequest{PublicKeySha256: first.GetPublicKeySha256(), CertificateSha256: first.GetCertificateSha256()})); err != nil {
		t.Fatal(err)
	}
	e.svc = reopen(t, e.svc, now)
	if !prepareKey(t, e.svc).GetAcknowledged() {
		t.Fatal("acknowledgment did not survive reopen")
	}

	// Past the latest jittered renewal time (notAfter-1h) the old certificate is
	// still usable, so renewal is due and the prior credential is retained.
	renewedAt := now.Add(19*24*time.Hour - 30*time.Minute)
	e.svc = reopen(t, e.svc, renewedAt)
	renewal := renew(t, e.svc)
	assertNoPrivateKey(t, e.svc, renewal)
	staged := durable(t, e.svc).GetPendingRenewal().GetEncryptionPrivateKey()
	if len(staged) != 32 || bytes.Equal(staged, initial) {
		t.Fatal("renewal did not stage a fresh recipient key")
	}
	priorBinding := testDelivery(e, deliveryRecipient(t, e.svc))
	priorSealed := seal(t, deliveryRecipient(t, e.svc), priorBinding, "prior")
	nextCert := e.fix.leaf(t, publicOf(durable(t, e.svc).GetPendingRenewal().GetPrivateKey()), e.device, e.generation, renewedAt.Add(-time.Minute), renewedAt.Add(20*24*time.Hour))
	if _, err := e.svc.CommitRenewal(t.Context(), connect.NewRequest(&agentv1.CommitRenewalRequest{IssuanceRequestId: renewal.GetIssuanceRequestId(), CertificatePem: nextCert})); err != nil {
		t.Fatal(err)
	}
	state := durable(t, e.svc)
	if !bytes.Equal(state.GetEncryptionPrivateKey(), staged) || !bytes.Equal(state.GetPriorCredential().GetEncryptionPrivateKey(), initial) || len(state.GetEncryptionKeyAcknowledgedSha256()) != 0 {
		t.Fatal("renewal did not promote the staged key, retain the prior one and clear the acknowledgment")
	}
	e.svc = reopen(t, e.svc, renewedAt.Add(time.Minute))
	renewed := prepareKey(t, e.svc)
	verifyAttestation(t, e, renewed)
	if renewed.GetAcknowledged() || bytes.Equal(renewed.GetPublicKeySha256(), first.GetPublicKeySha256()) {
		t.Fatal("renewed key inherited the prior acknowledgment or key")
	}

	currentBinding := testDelivery(e, deliveryRecipient(t, e.svc))
	for name, delivery := range map[string]struct {
		binding *agentv1.SecretDeliveryBinding
		sealed  []byte
		want    string
	}{
		"current": {currentBinding, seal(t, deliveryRecipient(t, e.svc), currentBinding, "current"), "current"},
		"prior":   {priorBinding, priorSealed, "prior"},
	} {
		material, err := openDelivery(t, e.svc, delivery.binding, delivery.sealed)
		if err != nil || string(material.GetOpaque()) != delivery.want {
			t.Fatalf("%s delivery did not open: %v", name, err)
		}
		secretseal.Clear(material)
	}
	// Past the prior credential's retention the old key is gone.
	e.svc = reopen(t, e.svc, renewedAt.Add(30*time.Minute))
	if _, err := openDelivery(t, e.svc, priorBinding, priorSealed); !errors.Is(err, errSecretDeliveryRejected) {
		t.Fatalf("retired prior key opened a delivery: %v", err)
	}
	if len(durable(t, e.svc).GetPriorCredential().GetEncryptionPrivateKey()) != 0 {
		t.Fatal("retired prior recipient key remained in protected state")
	}
}

func TestLegacyJournalLazilyGetsEncryptionKey(t *testing.T) {
	now := time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)
	e := enrollWithSession(t, now)
	// Model a journal installed before secret delivery existed.
	e.svc.mu.Lock()
	state, revision, err := e.svc.store.Load(t.Context())
	if err == nil {
		state.EncryptionPrivateKey = nil
		_, err = e.svc.store.Update(t.Context(), revision, state)
	}
	e.svc.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	e.svc = reopen(t, e.svc, now)
	svc := e.svc
	svc.mu.Lock()
	loaded, err := svc.enrolled(t.Context())
	if err == nil {
		_, err = svc.currentRecipientKeyID(loaded)
	}
	svc.mu.Unlock()
	if !errors.Is(err, errEncryptionKeyUnavailable) {
		t.Fatalf("legacy journal reported a recipient key: %v", err)
	}
	first := prepareKey(t, e.svc)
	if len(durable(t, e.svc).GetEncryptionPrivateKey()) != 32 {
		t.Fatal("legacy journal did not durably receive a recipient key")
	}
	verifyAttestation(t, e, first)
	e.svc = reopen(t, e.svc, now)
	if again := prepareKey(t, e.svc); !bytes.Equal(again.GetPublicKeySha256(), first.GetPublicKeySha256()) {
		t.Fatal("lazy recipient key was replaced on the next request")
	}
}

func TestOpenSecretDeliveryRefusesForeignBindings(t *testing.T) {
	now := time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)
	e := enrollWithSession(t, now)
	recipient := deliveryRecipient(t, e.svc)
	other, err := secretseal.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, err := secretseal.PublicKey(other)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*agentv1.SecretDeliveryBinding){
		"other device":     func(b *agentv1.SecretDeliveryBinding) { b.DeviceId = uuid.NewString() },
		"other generation": func(b *agentv1.SecretDeliveryBinding) { b.EnrollmentGeneration = uuid.NewString() },
		"other deployment": func(b *agentv1.SecretDeliveryBinding) { b.DeploymentId = uuid.NewString() },
	} {
		binding := testDelivery(e, recipient)
		change(binding)
		// Sealed honestly to this device's key under the foreign binding.
		if _, err := openDelivery(t, e.svc, binding, seal(t, recipient, binding, "x")); !errors.Is(err, errSecretDeliveryRejected) {
			t.Fatalf("%s: opened: %v", name, err)
		}
	}
	unknown := testDelivery(e, otherPublic)
	if _, err := openDelivery(t, e.svc, unknown, seal(t, otherPublic, unknown, "x")); !errors.Is(err, errSecretDeliveryRejected) {
		t.Fatalf("unknown recipient key opened: %v", err)
	}
	binding := testDelivery(e, recipient)
	sealed := seal(t, recipient, binding, "x")
	rebound := proto.CloneOf(binding)
	rebound.ActionId = uuid.NewString()
	if _, err := openDelivery(t, e.svc, rebound, sealed); !errors.Is(err, errSecretDeliveryRejected) {
		t.Fatalf("delivery opened under another action: %v", err)
	}
	if material, err := openDelivery(t, e.svc, binding, sealed); err != nil || string(material.GetOpaque()) != "x" {
		t.Fatalf("exact delivery did not open: %v", err)
	}
}
