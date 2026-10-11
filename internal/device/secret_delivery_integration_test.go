//go:build integration

package device

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/escrow"
	"lindm/internal/identity"
	"lindm/internal/secretseal"
)

var (
	deliveredSHA512 = "$6$lindmsalt$" + strings.Repeat("Z", 86)
	deliveredYes    = "$y$j9T$lindmsalt$" + strings.Repeat("Y", 43)
)

type deliveryFixture struct {
	*dispatchFixture
	recipient, private []byte
}

// newDeliveryFixture admits local users, configures escrow custody and returns
// a dispatch fixture without a registered device encryption key.
func newDeliveryFixture(t *testing.T) *deliveryFixture {
	t.Helper()
	f := &deliveryFixture{dispatchFixture: newDispatchFixtureWithDelegationAge(t, time.Hour, "systemd.service.v1", "local.user.v1")}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	f.service.Escrow, err = escrow.New(key, kek)
	clear(kek)
	if err != nil {
		t.Fatal(err)
	}
	f.private, err = secretseal.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.recipient, err = secretseal.PublicKey(f.private)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *deliveryFixture) registerRecipient(t *testing.T) {
	t.Helper()
	if _, err := registerKey(t, f.service, f.principal, encryptionKeyClaim(t, f.service, f.principal, f.recipient), f.key, 1); err != nil {
		t.Fatal(err)
	}
}

// storeSecret persists one version exactly as the secret store does.
func (f *deliveryFixture) storeSecret(t *testing.T, purpose resourcev1.SecretPurpose, material *agentv1.SecretMaterial) *resourcev1.SecretRef {
	t.Helper()
	id, subject := uuid.New(), uuid.New()
	plaintext, err := proto.MarshalOptions{Deterministic: true}.Marshal(material)
	if err != nil {
		t.Fatal(err)
	}
	binding, record, err := f.service.SealSecretVersion(id, 1, purpose, subject, plaintext)
	clear(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	q := devicedb.New(f.pool)
	if err := q.InsertManagedSecret(t.Context(), devicedb.InsertManagedSecretParams{ID: id, Purpose: int16(purpose), SubjectBindingID: subject, DisplayName: "delivery fixture", RequestID: uuid.New(), CreatedBy: f.actor.ID}); err != nil {
		t.Fatal(err)
	}
	if err := q.InsertManagedSecretVersion(t.Context(), devicedb.InsertManagedSecretVersionParams{SecretID: id, Version: 1, RequestID: uuid.New(), BindingDocument: binding, KeyID: record.KeyID, WrappedKey: record.WrappedKey, Ciphertext: record.Ciphertext, Reason: "delivery fixture", CreatedBy: f.actor.ID}); err != nil {
		t.Fatal(err)
	}
	return &resourcev1.SecretRef{SecretId: id.String(), Version: 1, Purpose: purpose, SubjectBindingId: subject.String()}
}

func passwordHashMaterial(hash string) *agentv1.SecretMaterial {
	return &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_PasswordHash{PasswordHash: []byte(hash)}}
}

// assignHashedUser publishes and assigns one local user whose password is ref.
func (f *deliveryFixture) assignHashedUser(t *testing.T, ref *resourcev1.SecretRef, algorithm resourcev1.PasswordHashAlgorithm) *resourcev1.ResourceDesiredState {
	t.Helper()
	desired := &resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: "alice"},
		State: &resourcev1.ResourceDesiredState_LocalUser{LocalUser: &resourcev1.LocalUserDesired{Name: "alice", Presence: resourcev1.Presence_PRESENCE_PRESENT,
			Password: &resourcev1.PasswordState{State: &resourcev1.PasswordState_Hashed{Hashed: &resourcev1.HashedPasswordPolicy{Hash: ref, Algorithm: algorithm}}}}},
	}
	user := dispatchProfileResource(desired)
	user.Ownership.Release = resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED
	publishDispatchResources(t, f.dispatchFixture, user)
	f.assign(t, nil)
	return desired
}

// rowsContain renders whole rows as text, so any column holding the material
// in plain or hex form would match.
func rowsContain(t *testing.T, f *deliveryFixture, needle string) bool {
	t.Helper()
	for _, table := range []string{"resource_actions", "resource_action_secrets", "audit_events", "managed_secret_versions"} {
		rows, err := f.pool.Query(t.Context(), "SELECT row_to_json(t)::text FROM "+table+" t")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var row string
			if err := rows.Scan(&row); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if strings.Contains(row, needle) || strings.Contains(row, hexEncode(needle)) {
				rows.Close()
				return true
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
	return false
}

func hexEncode(value string) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(value))
	for i := range len(value) {
		out = append(out, digits[value[i]>>4], digits[value[i]&15])
	}
	return string(out)
}

func TestServiceSecretDeliverySealsBoundMaterial(t *testing.T) {
	f := newDeliveryFixture(t)
	f.registerRecipient(t)
	ref := f.storeSecret(t, resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, passwordHashMaterial(deliveredSHA512))
	desired := f.assignHashedUser(t, ref, resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT)
	work := f.work(t)
	intent := f.intent(t, work)
	if len(intent.GetSecrets()) != 1 || len(work.GetSealedSecrets()) != 1 {
		t.Fatalf("minted %d manifest entries and %d deliveries", len(intent.GetSecrets()), len(work.GetSealedSecrets()))
	}
	delivery := intent.GetSecrets()[0]
	digest := sha256.Sum256(work.GetSealedSecrets()[0])
	expected := &agentv1.SecretDeliveryBinding{DeploymentId: f.service.DeploymentID.String(), DeviceId: f.principal.DeviceID.String(), EnrollmentGeneration: f.principal.GenerationID.String(), ActionId: intent.GetActionId(), Resource: desired.GetRef(), Secret: ref, RecipientKeySha256: secretseal.KeyID(f.recipient)}
	if !bytes.Equal(digest[:], delivery.GetSealedSha256()) || !proto.Equal(delivery.GetBinding(), expected) {
		t.Fatal("signed manifest does not bind the delivered ciphertext")
	}
	material, err := secretseal.Open(f.private, expected, work.GetSealedSecrets()[0])
	if err != nil || string(material.GetPasswordHash()) != deliveredSHA512 {
		t.Fatalf("device could not open its delivery: %v", err)
	}
	secretseal.Clear(material)

	replay := f.work(t)
	if replay.GetActionId() != work.GetActionId() || !bytes.Equal(replay.GetIntentEnvelope(), work.GetIntentEnvelope()) || len(replay.GetSealedSecrets()) != 1 || !bytes.Equal(replay.GetSealedSecrets()[0], work.GetSealedSecrets()[0]) {
		t.Fatal("retry did not return the exact stored delivery")
	}
	var reason, secretID, version string
	if err := f.pool.QueryRow(t.Context(), "SELECT reason, details->>'secret_id', details->>'version' FROM audit_events WHERE action='secret.delivered' AND resource_id=$1", work.GetActionId()).Scan(&reason, &secretID, &version); err != nil || reason != "" || secretID != ref.GetSecretId() || version != "1" {
		t.Fatalf("delivery audit reason=%q secret=%q version=%q, %v", reason, secretID, version, err)
	}
	if rowsContain(t, f, deliveredSHA512) {
		t.Fatal("persisted rows contain plaintext secret material")
	}

	// Losing secrets.manage after mint is an authority change: no start grant.
	f.service.Identity = operatorIdentity(t, f)
	request := &devicev1.AuthorizeResourceStartRequest{SessionEpoch: 1, ActionId: work.GetActionId(), ChallengeProof: f.sign(t, f.challenge(t, work), f.key)}
	_, err = f.service.AuthorizeResourceStart(f.deviceCtx, connect.NewRequest(request))
	dispatchError(t, err, connect.CodePermissionDenied, "authority_changed")
	assertDispatchClosure(t, f.dispatchFixture, work.GetActionId(), "authority_changed")
}

// A missing device key is transient: the resource waits visibly without a head
// block, and the next poll after registration mints with its delivery.
func TestServiceSecretDeliveryWaitsForDeviceKey(t *testing.T) {
	f := newDeliveryFixture(t)
	ref := f.storeSecret(t, resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, passwordHashMaterial(deliveredSHA512))
	f.assignHashedUser(t, ref, resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT)
	assertNoResourceWork(t, f.dispatchFixture)
	assertNoResourceWork(t, f.dispatchFixture)
	state := complianceState(t, f.dispatchFixture)
	if len(state.GetResources()) != 1 || state.GetResources()[0].GetDisposition() != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_PENDING || state.GetResources()[0].GetReason() != "device_encryption_key_unavailable" {
		t.Fatalf("missing key is not a visible pending wait: %v", state.GetResources())
	}
	var blocked string
	var actions int
	if err := f.pool.QueryRow(t.Context(), "SELECT blocked_reason, (SELECT count(*) FROM resource_actions) FROM resource_assignments WHERE id=$1", state.GetAssignment().GetAssignmentId()).Scan(&blocked, &actions); err != nil || blocked != "" || actions != 0 {
		t.Fatalf("missing key blocked the head or minted work: blocked=%q actions=%d err=%v", blocked, actions, err)
	}
	f.registerRecipient(t)
	work := f.work(t)
	intent := f.intent(t, work)
	if len(intent.GetSecrets()) != 1 || len(work.GetSealedSecrets()) != 1 {
		t.Fatal("registration did not unblock delivery")
	}
	material, err := secretseal.Open(f.private, intent.GetSecrets()[0].GetBinding(), work.GetSealedSecrets()[0])
	if err != nil || string(material.GetPasswordHash()) != deliveredSHA512 {
		t.Fatalf("device could not open its delivery: %v", err)
	}
	secretseal.Clear(material)
	state = complianceState(t, f.dispatchFixture)
	if state.GetResources()[0].GetReason() != "" || state.GetResources()[0].GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_PENDING {
		t.Fatalf("minted resource kept the waiting reason: %v", state.GetResources()[0])
	}
}

func TestServiceSecretDeliveryBlocksWithoutPrerequisites(t *testing.T) {
	for _, test := range []struct {
		name   string
		reason string
		setup  func(*testing.T, *deliveryFixture) (*resourcev1.SecretRef, resourcev1.PasswordHashAlgorithm)
	}{
		{"missing-secret", "secret_unavailable", func(t *testing.T, f *deliveryFixture) (*resourcev1.SecretRef, resourcev1.PasswordHashAlgorithm) {
			f.registerRecipient(t)
			return &resourcev1.SecretRef{SecretId: uuid.NewString(), Version: 1, Purpose: resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, SubjectBindingId: uuid.NewString()}, resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT
		}},
		{"subject", "secret_binding_mismatch", func(t *testing.T, f *deliveryFixture) (*resourcev1.SecretRef, resourcev1.PasswordHashAlgorithm) {
			f.registerRecipient(t)
			ref := f.storeSecret(t, resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, passwordHashMaterial(deliveredSHA512))
			ref.SubjectBindingId = uuid.NewString()
			return ref, resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT
		}},
		{"purpose", "secret_binding_mismatch", func(t *testing.T, f *deliveryFixture) (*resourcev1.SecretRef, resourcev1.PasswordHashAlgorithm) {
			f.registerRecipient(t)
			ref := f.storeSecret(t, resourcev1.SecretPurpose_SECRET_PURPOSE_WIFI_PSK, &agentv1.SecretMaterial{Material: &agentv1.SecretMaterial_WifiPsk{WifiPsk: []byte("correct horse battery")}})
			ref.Purpose = resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH
			return ref, resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT
		}},
		{"algorithm", "secret_binding_mismatch", func(t *testing.T, f *deliveryFixture) (*resourcev1.SecretRef, resourcev1.PasswordHashAlgorithm) {
			f.registerRecipient(t)
			return f.storeSecret(t, resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, passwordHashMaterial(deliveredYes)), resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT
		}},
		{"actor", "secret_delivery_unauthorized", func(t *testing.T, f *deliveryFixture) (*resourcev1.SecretRef, resourcev1.PasswordHashAlgorithm) {
			f.registerRecipient(t)
			f.service.Identity = operatorIdentity(t, f)
			return f.storeSecret(t, resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, passwordHashMaterial(deliveredSHA512)), resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newDeliveryFixture(t)
			ref, algorithm := test.setup(t, f)
			f.assignHashedUser(t, ref, algorithm)
			assertNoResourceWork(t, f.dispatchFixture)
			state := complianceState(t, f.dispatchFixture)
			if len(state.GetResources()) != 1 || state.GetResources()[0].GetReason() != test.reason {
				t.Fatalf("visible block = %v", state.GetResources())
			}
			var actions, deliveries int
			if err := f.pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM resource_actions), (SELECT count(*) FROM resource_action_secrets)").Scan(&actions, &deliveries); err != nil || actions != 0 || deliveries != 0 {
				t.Fatalf("blocked head minted work: actions=%d deliveries=%d err=%v", actions, deliveries, err)
			}
			if rowsContain(t, f, deliveredSHA512) || rowsContain(t, f, deliveredYes) {
				t.Fatal("persisted rows contain plaintext secret material")
			}
		})
	}
}

// operatorIdentity observes the same directory group through a policy that
// grants resources.assign without secrets.manage.
func operatorIdentity(t *testing.T, f *deliveryFixture) *identity.Service {
	t.Helper()
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(devFixture(t), name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(data))
	}
	service, err := identity.New(t.Context(), f.pool, identity.Config{Issuer: "https://localhost:18443/realms/lindm", ClientID: "lindm-console", ClientSecret: read("console-secret"), DirectoryClientID: "lindm-directory", DirectoryClientSecret: read("directory-secret"), PublicURL: "https://localhost:18444", Policy: &authv1.AuthorizationPolicy{GroupBindings: []*authv1.GroupBinding{{Group: "/" + f.directory.name, Role: identity.RoleOperator}}}, HTTPClient: f.directory.client})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	return service
}
