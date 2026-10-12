package secrets

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/resource"
	"lindm/internal/rpcreason"
)

var (
	errSecretInUse   = rpcreason.Error(connect.CodeFailedPrecondition, "secret_in_use")
	errSecretDeleted = rpcreason.Error(connect.CodeFailedPrecondition, "secret_deleted")
)

// secretUseNeedle is the canonical ID text every stored SecretRef to id holds;
// resource validation rejects any other spelling.
func secretUseNeedle(id uuid.UUID) []byte {
	return []byte(id.String())
}

// secretSettingUse names one stored setting and the version of id it pins.
// The stored record is a ProfileResource in both profiles and device heads; a
// record that does not decode to a typed reference keeps version zero.
func secretSettingUse(kind int16, key string, record []byte, id uuid.UUID) *adminv1.SecretSettingUse {
	use := &adminv1.SecretSettingUse{Resource: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind(kind), CanonicalKey: key}}
	stored := new(policyv1.ProfileResource)
	if proto.Unmarshal(record, stored) != nil {
		return use
	}
	desired := stored.GetDesired()
	switch {
	case desired.GetNetworkConnection() != nil:
		use.Name = desired.GetNetworkConnection().GetDisplayName()
	case desired.GetLocalUser() != nil:
		use.Name = desired.GetLocalUser().GetName()
	case desired.GetDirectoryClient() != nil:
		use.Name = desired.GetDirectoryClient().GetRealm()
	}
	refs, err := resource.SecretRefs(desired, resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE)
	if err != nil {
		return use
	}
	for _, ref := range refs {
		if parsed, err := uuid.Parse(ref.GetSecretId()); err == nil && parsed == id {
			use.Version = max(use.Version, ref.GetVersion())
		}
	}
	return use
}

// loadSecretUses reads current references to id inside the caller's snapshot.
func loadSecretUses(ctx context.Context, q *devicedb.Queries, id uuid.UUID, unrestricted bool, scopes []byte) (*adminv1.ListSecretUsesResponse, error) {
	needle := secretUseNeedle(id)
	counts, err := q.CountSecretUses(ctx, devicedb.CountSecretUsesParams{Needle: needle, ScopeUnrestricted: unrestricted, Scopes: scopes})
	if err != nil {
		return nil, err
	}
	response := &adminv1.ListSecretUsesResponse{ProfileCount: uint32(counts.Profiles), DeviceCount: uint32(counts.Devices), VisibleDeviceCount: uint32(counts.VisibleDevices)}
	profiles, err := q.ListSecretProfileUses(ctx, needle)
	if err != nil {
		return nil, err
	}
	for _, row := range profiles {
		if row.RevisionNumber <= 0 {
			return nil, core.ErrInternalState
		}
		last := len(response.Profiles) - 1
		if last < 0 || response.Profiles[last].GetProfileId() != row.ProfileID.String() {
			response.Profiles = append(response.Profiles, &adminv1.SecretProfileUse{ProfileId: row.ProfileID.String(), ProfileName: row.Name, RevisionNumber: uint64(row.RevisionNumber)})
			last++
		}
		response.Profiles[last].Settings = append(response.Profiles[last].Settings, secretSettingUse(row.ResourceKind, row.CanonicalKey, row.ResourceProto, id))
	}
	devices, err := q.ListSecretDeviceUses(ctx, devicedb.ListSecretDeviceUsesParams{Needle: needle, ScopeUnrestricted: unrestricted, Scopes: scopes})
	if err != nil {
		return nil, err
	}
	for _, row := range devices {
		last := len(response.Devices) - 1
		if last < 0 || response.Devices[last].GetDeviceId() != row.DeviceID.String() {
			response.Devices = append(response.Devices, &adminv1.SecretDeviceUse{DeviceId: row.DeviceID.String(), Hostname: row.Hostname})
			last++
		}
		response.Devices[last].Settings = append(response.Devices[last].Settings, secretSettingUse(row.ResourceKind, row.CanonicalKey, row.Document, id))
	}
	return response, nil
}

// ListSecretUses returns metadata only. Devices outside the caller's scope
// are counted but not named.
func (s *Service) ListSecretUses(ctx context.Context, req *connect.Request[adminv1.ListSecretUsesRequest]) (*connect.Response[adminv1.ListSecretUsesResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionManageSecrets)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_argument")
	}
	unrestricted, scopes, err := core.DeviceScopeFilter(actor, identity.PermissionManageSecrets)
	if err != nil {
		return nil, core.MapErr(err)
	}
	id := uuid.MustParse(req.Msg.GetSecretId())
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	if _, err := loadSecretSummary(ctx, q, id); err != nil {
		return nil, core.MapErr(err)
	}
	response, err := loadSecretUses(ctx, q, id, unrestricted, scopes)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(response), nil
}

// DeleteSecret erases every version's material while nothing current
// references the secret. Publication and assignment do not consult the store,
// so a reference added after this check fails closed at delivery with
// secret_unavailable rather than reviving material.
func (s *Service) DeleteSecret(ctx context.Context, req *connect.Request[adminv1.DeleteSecretRequest]) (*connect.Response[adminv1.DeleteSecretResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageSecrets)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) {
		return nil, core.Invalid("invalid_secret")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	requestID := uuid.MustParse(req.Msg.GetRequestId())
	id := uuid.MustParse(req.Msg.GetSecretId())
	const method = "DeleteSecret"
	digest := core.MutationDigest(method, id.String(), req.Msg.GetReason())
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageSecrets, func(ctx context.Context, q *devicedb.Queries) error {
		_, owned, err := s.BeginAdminRequest(ctx, q, actor.ID, method, requestID, digest)
		if err != nil || !owned {
			return err
		}
		if _, err := q.LockManagedSecret(ctx, id); err != nil {
			return core.NotFoundIfMissing(err)
		}
		uses, err := q.CountSecretUses(ctx, devicedb.CountSecretUsesParams{Needle: secretUseNeedle(id), ScopeUnrestricted: true, Scopes: []byte("[]")})
		if err != nil {
			return err
		}
		if uses.Profiles != 0 || uses.Devices != 0 {
			return errSecretInUse
		}
		if err := q.EraseManagedSecretVersions(ctx, id); err != nil {
			return err
		}
		if err := q.DeleteManagedSecret(ctx, devicedb.DeleteManagedSecretParams{ID: id, DeletedBy: &actor.ID}); err != nil {
			return err
		}
		if err := core.DispatchAudit(ctx, q, &actor.ID, auditkind.SecretDeleted, id, req.Msg.GetReason()); err != nil {
			return err
		}
		return core.CompleteAdmin(ctx, q, actor.ID, method, requestID, uuid.Nil, uuid.Nil, time.Unix(0, 0).UTC())
	})
	if err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.DeleteSecretResponse{}), nil
}
