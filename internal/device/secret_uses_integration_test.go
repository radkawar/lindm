//go:build integration

package device

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/identity"
)

func (f *deliveryFixture) secretUses(t *testing.T, ref *resourcev1.SecretRef) *adminv1.ListSecretUsesResponse {
	t.Helper()
	response, err := f.service.ListSecretUses(f.adminCtx, connect.NewRequest(&adminv1.ListSecretUsesRequest{SecretId: ref.GetSecretId()}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg
}

// The blast radius an administrator sees before deletion is the same set the
// server enforces: a referenced secret cannot be deleted, and deletion of an
// unreferenced one erases its material while history stays auditable.
func TestSecretUsesAndDeletion(t *testing.T) {
	f := newDeliveryFixture(t)
	ref := f.storeSecret(t, resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, passwordHashMaterial(deliveredSHA512))
	unused := f.storeSecret(t, resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH, passwordHashMaterial(deliveredYes))

	desired := &resourcev1.ResourceDesiredState{
		Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_LOCAL_USER, CanonicalKey: "alice"},
		State: &resourcev1.ResourceDesiredState_LocalUser{LocalUser: &resourcev1.LocalUserDesired{Name: "alice", Presence: resourcev1.Presence_PRESENCE_PRESENT,
			Password: &resourcev1.PasswordState{State: &resourcev1.PasswordState_Hashed{Hashed: &resourcev1.HashedPasswordPolicy{Hash: ref, Algorithm: resourcev1.PasswordHashAlgorithm_PASSWORD_HASH_ALGORITHM_SHA512_CRYPT}}}}},
	}
	user := dispatchProfileResource(desired)
	user.Ownership.Release = resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED
	publishDispatchResources(t, f.dispatchFixture, user)

	uses := f.secretUses(t, ref)
	if uses.GetProfileCount() != 1 || uses.GetDeviceCount() != 0 || len(uses.GetProfiles()) != 1 || len(uses.GetDevices()) != 0 {
		t.Fatalf("published profile uses: %v", uses)
	}
	profile := uses.GetProfiles()[0]
	if profile.GetProfileId() != f.revision.GetProfileId() || profile.GetProfileName() != "Heterogeneous dispatch" || profile.GetRevisionNumber() != 1 || len(profile.GetSettings()) != 1 {
		t.Fatalf("profile use: %v", profile)
	}
	if setting := profile.GetSettings()[0]; !proto.Equal(setting.GetResource(), desired.GetRef()) || setting.GetVersion() != 1 || setting.GetName() != "alice" {
		t.Fatalf("setting use: %v", setting)
	}
	if other := f.secretUses(t, unused); other.GetProfileCount() != 0 || other.GetDeviceCount() != 0 || len(other.GetProfiles()) != 0 {
		t.Fatalf("unreferenced secret reported uses: %v", other)
	}

	f.assign(t, nil)
	uses = f.secretUses(t, ref)
	if uses.GetDeviceCount() != 1 || uses.GetVisibleDeviceCount() != 1 || len(uses.GetDevices()) != 1 {
		t.Fatalf("assigned device uses: %v", uses)
	}
	if device := uses.GetDevices()[0]; device.GetDeviceId() != f.principal.DeviceID.String() || len(device.GetSettings()) != 1 || device.GetSettings()[0].GetVersion() != 1 {
		t.Fatalf("device use: %v", device)
	}

	// A scoped manager learns how many devices use it, never which ones.
	scoped := identity.WithPrincipal(t.Context(), scopedSecretPrincipal(f.actor, identity.PermissionManageSecrets))
	hidden, err := f.service.ListSecretUses(scoped, connect.NewRequest(&adminv1.ListSecretUsesRequest{SecretId: ref.GetSecretId()}))
	if err != nil || hidden.Msg.GetDeviceCount() != 1 || hidden.Msg.GetVisibleDeviceCount() != 0 || len(hidden.Msg.GetDevices()) != 0 {
		t.Fatalf("scoped uses: %v %v", hidden, err)
	}
	if _, err := f.service.DeleteSecret(scoped, connect.NewRequest(&adminv1.DeleteSecretRequest{RequestId: uuid.NewString(), SecretId: unused.GetSecretId(), Reason: "scoped delete"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("scoped delete: %v", err)
	}

	inUse := &adminv1.DeleteSecretRequest{RequestId: uuid.NewString(), SecretId: ref.GetSecretId(), Reason: "retire the old password"}
	_, err = f.service.DeleteSecret(f.adminCtx, connect.NewRequest(inUse))
	dispatchError(t, err, connect.CodeFailedPrecondition, "secret_in_use")
	if _, err := f.service.GetSecret(f.adminCtx, connect.NewRequest(&adminv1.GetSecretRequest{SecretId: ref.GetSecretId()})); err != nil {
		t.Fatalf("refused delete changed the secret: %v", err)
	}
	// The refused request left no completed record: the same ID may retry later.
	var recorded int
	if err := f.pool.QueryRow(t.Context(), "SELECT count(*) FROM device_admin_requests WHERE request_id=$1", inUse.GetRequestId()).Scan(&recorded); err != nil || recorded != 0 {
		t.Fatalf("refused delete recorded %d requests: %v", recorded, err)
	}
	// Delivery still works: refusal must not have erased material.
	f.registerRecipient(t)
	if work := f.work(t); work == nil || len(work.GetSealedSecrets()) != 1 {
		t.Fatalf("referenced secret no longer delivers: %v", work)
	}

	remove := &adminv1.DeleteSecretRequest{RequestId: uuid.NewString(), SecretId: unused.GetSecretId(), Reason: "credential no longer needed"}
	if _, err := f.service.DeleteSecret(f.adminCtx, connect.NewRequest(remove)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.DeleteSecret(f.adminCtx, connect.NewRequest(remove)); err != nil {
		t.Fatalf("exact delete retry: %v", err)
	}
	changed := proto.CloneOf(remove)
	changed.Reason = "a different reason"
	if _, err := f.service.DeleteSecret(f.adminCtx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("request ID reused with a different payload: %v", err)
	}
	if _, err := f.service.GetSecret(f.adminCtx, connect.NewRequest(&adminv1.GetSecretRequest{SecretId: unused.GetSecretId()})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("deleted secret still readable: %v", err)
	}
	if _, err := f.service.ListSecretUses(f.adminCtx, connect.NewRequest(&adminv1.ListSecretUsesRequest{SecretId: unused.GetSecretId()})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("deleted secret uses: %v", err)
	}
	listed, err := f.service.ListSecrets(f.adminCtx, connect.NewRequest(&adminv1.ListSecretsRequest{}))
	if err != nil || len(listed.Msg.GetSecrets()) != 1 || listed.Msg.GetSecrets()[0].GetSecretId() != ref.GetSecretId() {
		t.Fatalf("list after delete: %v %v", listed, err)
	}
	if _, err := f.service.RotateSecret(f.adminCtx, connect.NewRequest(&adminv1.RotateSecretRequest{RequestId: uuid.NewString(), SecretId: unused.GetSecretId(), ExpectedVersion: 1, Material: passwordHashMaterial(deliveredSHA512), Reason: "rotate deleted"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("rotate deleted secret: %v", err)
	}
	var erased bool
	var reason string
	if err := f.pool.QueryRow(t.Context(), "SELECT bool_and(octet_length(wrapped_key) = 0 AND octet_length(ciphertext) = 0) FROM managed_secret_versions WHERE secret_id=$1", unused.GetSecretId()).Scan(&erased); err != nil || !erased {
		t.Fatalf("material not erased: %v", err)
	}
	if err := f.pool.QueryRow(t.Context(), "SELECT reason FROM audit_events WHERE action='secret.deleted' AND resource_id=$1", unused.GetSecretId()).Scan(&reason); err != nil || reason != remove.GetReason() {
		t.Fatalf("delete audit reason=%q: %v", reason, err)
	}
}
