package secrets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"

	"lindm/internal/device/core"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/resource"
	"lindm/internal/secretseal"
)

// Visible reasons for a resource whose secret cannot be delivered. Each one
// blocks the head instead of minting work that lacks its material, except a
// missing device key: registration follows in the device's management cycle,
// so the resource only waits, visibly pending, and mints once it registers.
const (
	secretBlockUnavailable    = "secret_unavailable"
	secretBlockMismatch       = "secret_binding_mismatch"
	SecretWaitDeviceKey       = "device_encryption_key_unavailable"
	secretBlockUnauthorized   = "secret_delivery_unauthorized"
	secretDeliveredAuditEvent = "secret.delivered"
)

// ResourceSecretDelivery is one sealed delivery ready to be signed and stored.
type ResourceSecretDelivery struct {
	Manifest *agentv1.ResourceSecretDelivery
	sealed   []byte
}

// sealResourceSecrets resolves, authorizes and seals every SecretRef that the
// intent for action id will reference, inside the caller's locked dispatch
// transaction. A non-empty reason means nothing is minted.
// Plaintext material exists only between openManagedSecret and Seal.
func (s *Service) SealResourceSecrets(ctx context.Context, q *devicedb.Queries, approval *identity.Authorization, principal core.DevicePrincipal, action uuid.UUID, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) ([]ResourceSecretDelivery, string, error) {
	refs, err := resource.SecretRefs(desired, operation)
	if err != nil {
		return nil, secretBlockMismatch, nil
	}
	if len(refs) == 0 {
		return nil, "", nil
	}
	if reason, err := SecretDeliveryAuthority(ctx, q, approval, principal.DeviceID); reason != "" || err != nil {
		return nil, reason, err
	}
	public, err := CurrentDeviceEncryptionKey(ctx, q, principal.GenerationID)
	if errors.Is(err, ErrDeviceEncryptionKeyUnavailable) {
		return nil, SecretWaitDeviceKey, nil
	}
	if err != nil {
		return nil, "", err
	}
	recipient := secretseal.KeyID(public)
	deliveries := make([]ResourceSecretDelivery, 0, len(refs))
	for _, ref := range refs {
		binding := &agentv1.SecretDeliveryBinding{
			DeploymentId: s.DeploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(),
			ActionId: action.String(), Resource: proto.CloneOf(desired.GetRef()), Secret: ref, RecipientKeySha256: recipient,
		}
		sealed, reason, err := s.sealResourceSecret(ctx, q, public, binding, desired)
		if reason != "" || err != nil {
			return nil, reason, err
		}
		digest := sha256.Sum256(sealed)
		deliveries = append(deliveries, ResourceSecretDelivery{Manifest: &agentv1.ResourceSecretDelivery{Binding: binding, SealedSha256: digest[:]}, sealed: sealed})
	}
	return deliveries, "", nil
}

// waitResource records a visible, non-terminal reason on a candidate
// without changing its disposition. It writes only on change, so repeated
// polls are free. Minting later sets the dispatched disposition and clears it.
func WaitResource(ctx context.Context, q *devicedb.Queries, assignment uuid.UUID, rows []devicedb.ResourceAssignmentResource, candidate *policyv1.ProfileResource, reason string) error {
	id, err := core.ParseUUID(candidate.GetResourceId())
	if err != nil {
		return core.ErrInternalState
	}
	for _, row := range rows {
		if row.ResourceID != id {
			continue
		}
		if row.Reason == reason {
			return nil
		}
		return q.SetAssignmentResourceDisposition(ctx, devicedb.SetAssignmentResourceDispositionParams{AssignmentID: assignment, ResourceID: id, Disposition: row.Disposition, Reason: reason})
	}
	return core.ErrInternalState
}

func (s *Service) sealResourceSecret(ctx context.Context, q *devicedb.Queries, public []byte, binding *agentv1.SecretDeliveryBinding, desired *resourcev1.ResourceDesiredState) ([]byte, string, error) {
	material, err := s.OpenManagedSecret(ctx, q, binding.GetSecret())
	switch {
	case errors.Is(err, ErrSecretUnavailable):
		return nil, secretBlockUnavailable, nil
	case errors.Is(err, ErrSecretBindingMismatch):
		return nil, secretBlockMismatch, nil
	case err != nil:
		return nil, "", err
	}
	defer secretseal.Clear(material)
	if binding.GetSecret().GetPurpose() == resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH {
		// The traversal admits PASSWORD_HASH only in HashedPasswordPolicy.hash,
		// which exists only in LocalUserDesired.password.
		hashed := desired.GetLocalUser().GetPassword().GetHashed()
		if hashed == nil || !proto.Equal(hashed.GetHash(), binding.GetSecret()) || !resource.PasswordHashMatches(hashed.GetAlgorithm(), material.GetPasswordHash()) {
			return nil, secretBlockMismatch, nil
		}
	}
	sealed, err := secretseal.Seal(public, binding, material)
	if err != nil {
		return nil, "", fmt.Errorf("seal resource secret: %w", err)
	}
	return sealed, "", nil
}

// secretDeliveryAuthority requires the fenced assigning-actor approval to also
// carry secrets.manage within this device's scope. The approval's principal is
// the fresh directory observation LockAuthorization rechecks in this transaction.
func SecretDeliveryAuthority(ctx context.Context, q *devicedb.Queries, approval *identity.Authorization, device uuid.UUID) (string, error) {
	if approval == nil || !identity.Authorize(approval.Principal(), identity.PermissionManageSecrets) {
		return secretBlockUnauthorized, nil
	}
	if err := core.RequireDeviceScope(ctx, q, approval.Principal(), identity.PermissionManageSecrets, device); err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return secretBlockUnauthorized, nil
		}
		return "", err
	}
	return "", nil
}

// storeResourceSecrets persists the exact sealed bytes beside the inserted
// action and audits each delivery by identifiers only.
func StoreResourceSecrets(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action uuid.UUID, deliveries []ResourceSecretDelivery) error {
	for i, delivery := range deliveries {
		binding := delivery.Manifest.GetBinding()
		secret, err := core.ParseUUID(binding.GetSecret().GetSecretId())
		if err != nil {
			return core.ErrInternalState
		}
		version := binding.GetSecret().GetVersion()
		if err := q.InsertResourceActionSecret(ctx, devicedb.InsertResourceActionSecretParams{ActionID: action, Ordinal: int16(i), SecretID: secret, Version: int64(version), RecipientKeySha256: binding.GetRecipientKeySha256(), Sealed: delivery.sealed}); err != nil {
			return err
		}
		if err := core.DispatchSystemAudit(ctx, q, actor, secretDeliveredAuditEvent, action, "secret_id", secret.String(), "version", strconv.FormatUint(version, 10)); err != nil {
			return err
		}
	}
	return nil
}

// resourceActionSecrets returns the stored sealed bytes for a replay and
// requires them to still match the signed manifest exactly.
func ResourceActionSecrets(ctx context.Context, q *devicedb.Queries, action devicedb.ResourceAction) ([][]byte, error) {
	intent := new(agentv1.ResourceExecutionIntent)
	if err := proto.Unmarshal(action.IntentDocument, intent); err != nil {
		return nil, core.ErrInternalState
	}
	if len(intent.GetSecrets()) == 0 {
		return nil, nil
	}
	sealed, err := q.ListResourceActionSecrets(ctx, action.ID)
	if err != nil {
		return nil, err
	}
	if len(sealed) != len(intent.GetSecrets()) {
		return nil, core.ErrInternalState
	}
	for i, delivery := range intent.GetSecrets() {
		digest := sha256.Sum256(sealed[i])
		if !bytes.Equal(digest[:], delivery.GetSealedSha256()) {
			return nil, core.ErrInternalState
		}
	}
	return sealed, nil
}
