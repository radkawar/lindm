package secrets

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/escrow"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/secretseal"
)

var (
	ErrSecretUnavailable     = rpcreason.Error(connect.CodeFailedPrecondition, "secret_unavailable")
	ErrSecretBindingMismatch = rpcreason.Error(connect.CodeFailedPrecondition, "secret_binding_mismatch")
	errSecretPurposeMismatch = core.Invalid("secret_purpose_mismatch")
	errSecretVersionConflict = rpcreason.Error(connect.CodeFailedPrecondition, "secret_version_conflict")
	errSecretRequestReused   = rpcreason.Error(connect.CodeAlreadyExists, "request_id_reused")
	errEscrowUnconfigured    = rpcreason.Error(connect.CodeFailedPrecondition, "escrow_unconfigured")
	errEscrowCustodyRejected = rpcreason.Error(connect.CodeFailedPrecondition, "escrow_custody_rejected")
)

const secretVersionPage = 100

// secretMaterialMatches pins the typed material arm to the immutable purpose.
func secretMaterialMatches(purpose resourcev1.SecretPurpose, material *agentv1.SecretMaterial) bool {
	switch material.GetMaterial().(type) {
	case *agentv1.SecretMaterial_PasswordHash:
		return purpose == resourcev1.SecretPurpose_SECRET_PURPOSE_PASSWORD_HASH
	case *agentv1.SecretMaterial_WifiPsk:
		return purpose == resourcev1.SecretPurpose_SECRET_PURPOSE_WIFI_PSK
	case *agentv1.SecretMaterial_Opaque:
		return purpose > resourcev1.SecretPurpose_SECRET_PURPOSE_WIFI_PSK && resourcev1.SecretPurpose_name[int32(purpose)] != ""
	default:
		return false
	}
}

func secretBindingDocument(id uuid.UUID, version int64, purpose resourcev1.SecretPurpose, subject uuid.UUID) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(&resourcev1.SecretRef{SecretId: id.String(), Version: uint64(version), Purpose: purpose, SubjectBindingId: subject.String()})
}

// sealSecretVersion returns the storage envelope; the caller owns plaintext.
func (s *Service) SealSecretVersion(id uuid.UUID, version int64, purpose resourcev1.SecretPurpose, subject uuid.UUID, plaintext []byte) ([]byte, *escrow.SecretRecord, error) {
	binding, err := secretBindingDocument(id, version, purpose, subject)
	if err != nil {
		return nil, nil, err
	}
	record, err := s.Escrow.SealSecret(binding, plaintext)
	if err != nil {
		return nil, nil, errEscrowCustodyRejected
	}
	return binding, record, nil
}

// storedMaterialEqual opens one stored version and compares in constant time.
func (s *Service) storedMaterialEqual(binding []byte, record *escrow.SecretRecord, plaintext []byte) (bool, error) {
	opened, err := s.Escrow.OpenSecret(binding, record)
	if err != nil {
		return false, errEscrowCustodyRejected
	}
	equal := subtle.ConstantTimeCompare(opened, plaintext) == 1
	clear(opened)
	return equal, nil
}

func secretSummary(id uuid.UUID, purpose int16, subject uuid.UUID, name string, version int64, createdBy uuid.UUID, createdAt, updatedAt pgtype.Timestamptz, creator string) (*adminv1.SecretSummary, error) {
	created, ok := core.FiniteTime(createdAt)
	updated, updatedOK := core.FiniteTime(updatedAt)
	if !ok || !updatedOK || version <= 0 {
		return nil, core.ErrInternalState
	}
	return &adminv1.SecretSummary{
		SecretId: id.String(), Purpose: resourcev1.SecretPurpose(purpose), DisplayName: name,
		SubjectBindingId: subject.String(), CurrentVersion: uint64(version),
		CreatedAt: timestamppb.New(created), UpdatedAt: timestamppb.New(updated),
		CreatedBy: createdBy.String(), CreatedByDisplayName: creator,
	}, nil
}

func loadSecretSummary(ctx context.Context, q *devicedb.Queries, id uuid.UUID) (*adminv1.SecretSummary, error) {
	row, err := q.GetManagedSecretSummary(ctx, id)
	if err != nil {
		return nil, core.NotFoundIfMissing(err)
	}
	return secretSummary(row.ID, row.Purpose, row.SubjectBindingID, row.DisplayName, row.CurrentVersion, row.CreatedBy, row.CreatedAt, row.UpdatedAt, row.CreatorDisplayName)
}

// replayedSecretVersion resolves an exact retry of a create or rotate request.
// Any difference, including material, is a reused request ID.
func (s *Service) replayedSecretVersion(ctx context.Context, q *devicedb.Queries, requestID, actor uuid.UUID, match func(devicedb.GetManagedSecretVersionByRequestRow) bool, plaintext []byte) (uuid.UUID, error) {
	row, err := q.GetManagedSecretVersionByRequest(ctx, requestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil
	}
	if err != nil {
		return uuid.Nil, err
	}
	if row.CreatedBy != actor || !match(row) {
		return uuid.Nil, errSecretRequestReused
	}
	if row.Deleted {
		return uuid.Nil, errSecretDeleted
	}
	equal, err := s.storedMaterialEqual(row.BindingDocument, &escrow.SecretRecord{KeyID: row.KeyID, WrappedKey: row.WrappedKey, Ciphertext: row.Ciphertext}, plaintext)
	if err != nil {
		return uuid.Nil, err
	}
	if !equal {
		return uuid.Nil, errSecretRequestReused
	}
	return row.SecretID, nil
}

func (s *Service) CreateSecret(ctx context.Context, req *connect.Request[adminv1.CreateSecretRequest]) (*connect.Response[adminv1.CreateSecretResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageSecrets)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason(), req.Msg.GetDisplayName()) || !secretMaterialMatches(req.Msg.GetPurpose(), req.Msg.GetMaterial()) {
		return nil, core.Invalid("invalid_secret")
	}
	if s.Escrow == nil {
		return nil, errEscrowUnconfigured
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	plaintext, err := proto.MarshalOptions{Deterministic: true}.Marshal(req.Msg.GetMaterial())
	if err != nil {
		return nil, core.Invalid("invalid_secret")
	}
	defer clear(plaintext)
	requestID := uuid.MustParse(req.Msg.GetRequestId())
	purpose := req.Msg.GetPurpose()
	var summary *adminv1.SecretSummary
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageSecrets, func(ctx context.Context, q *devicedb.Queries) error {
		id, err := s.replayedSecretVersion(ctx, q, requestID, actor.ID, func(row devicedb.GetManagedSecretVersionByRequestRow) bool {
			return row.Version == 1 && row.Purpose == int16(purpose) && row.DisplayName == req.Msg.GetDisplayName()
		}, plaintext)
		if err != nil {
			return err
		}
		if id == uuid.Nil {
			id = uuid.New()
			subject := uuid.New()
			binding, record, err := s.SealSecretVersion(id, 1, purpose, subject, plaintext)
			if err != nil {
				return err
			}
			if err := q.InsertManagedSecret(ctx, devicedb.InsertManagedSecretParams{ID: id, Purpose: int16(purpose), SubjectBindingID: subject, DisplayName: req.Msg.GetDisplayName(), RequestID: requestID, CreatedBy: actor.ID}); err != nil {
				return err
			}
			if err := q.InsertManagedSecretVersion(ctx, devicedb.InsertManagedSecretVersionParams{SecretID: id, Version: 1, RequestID: requestID, BindingDocument: binding, KeyID: record.KeyID, WrappedKey: record.WrappedKey, Ciphertext: record.Ciphertext, Reason: req.Msg.GetReason(), CreatedBy: actor.ID}); err != nil {
				return err
			}
			if err := core.DispatchAudit(ctx, q, &actor.ID, "secret.created", id, req.Msg.GetReason()); err != nil {
				return err
			}
		}
		summary, err = loadSecretSummary(ctx, q, id)
		return err
	})
	if err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.CreateSecretResponse{Secret: summary}), nil
}

func (s *Service) RotateSecret(ctx context.Context, req *connect.Request[adminv1.RotateSecretRequest]) (*connect.Response[adminv1.RotateSecretResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.RequireUnrestricted(ctx, identity.PermissionManageSecrets)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) || req.Msg.GetExpectedVersion() >= 1<<62 {
		return nil, core.Invalid("invalid_secret")
	}
	if s.Escrow == nil {
		return nil, errEscrowUnconfigured
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	plaintext, err := proto.MarshalOptions{Deterministic: true}.Marshal(req.Msg.GetMaterial())
	if err != nil {
		return nil, core.Invalid("invalid_secret")
	}
	defer clear(plaintext)
	requestID := uuid.MustParse(req.Msg.GetRequestId())
	id := uuid.MustParse(req.Msg.GetSecretId())
	expected := int64(req.Msg.GetExpectedVersion())
	var summary *adminv1.SecretSummary
	err = s.WithinUnrestrictedAuthorization(ctx, actor, identity.PermissionManageSecrets, func(ctx context.Context, q *devicedb.Queries) error {
		replay, err := s.replayedSecretVersion(ctx, q, requestID, actor.ID, func(row devicedb.GetManagedSecretVersionByRequestRow) bool {
			return row.SecretID == id && row.Version == expected+1
		}, plaintext)
		if err != nil {
			return err
		}
		if replay == uuid.Nil {
			secret, err := q.LockManagedSecret(ctx, id)
			if err != nil {
				return core.NotFoundIfMissing(err)
			}
			purpose := resourcev1.SecretPurpose(secret.Purpose)
			if !secretMaterialMatches(purpose, req.Msg.GetMaterial()) {
				return errSecretPurposeMismatch
			}
			if secret.CurrentVersion != expected {
				return errSecretVersionConflict
			}
			version := expected + 1
			binding, record, err := s.SealSecretVersion(id, version, purpose, secret.SubjectBindingID, plaintext)
			if err != nil {
				return err
			}
			if err := q.InsertManagedSecretVersion(ctx, devicedb.InsertManagedSecretVersionParams{SecretID: id, Version: version, RequestID: requestID, BindingDocument: binding, KeyID: record.KeyID, WrappedKey: record.WrappedKey, Ciphertext: record.Ciphertext, Reason: req.Msg.GetReason(), CreatedBy: actor.ID}); err != nil {
				return err
			}
			advanced, err := q.AdvanceManagedSecretVersion(ctx, devicedb.AdvanceManagedSecretVersionParams{ID: id, Version: version})
			if err != nil {
				return err
			}
			if advanced != 1 {
				return errSecretVersionConflict
			}
			if err := core.DispatchAudit(ctx, q, &actor.ID, "secret.rotated", id, req.Msg.GetReason()); err != nil {
				return err
			}
		}
		summary, err = loadSecretSummary(ctx, q, id)
		return err
	})
	if err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.RotateSecretResponse{Secret: summary}), nil
}

// ListSecrets and GetSecret return metadata only, never material or envelopes.
func (s *Service) ListSecrets(ctx context.Context, req *connect.Request[adminv1.ListSecretsRequest]) (*connect.Response[adminv1.ListSecretsResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	if _, err := s.Require(ctx, identity.PermissionManageSecrets); err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_argument")
	}
	params := devicedb.ListManagedSecretsParams{RowLimit: core.PageLimit(req.Msg.GetPageSize()) + 1, NamePrefix: req.Msg.GetNamePrefix()}
	if token := req.Msg.GetPageToken(); token != "" {
		when, id, err := core.DecodeCursor(token)
		if err != nil {
			return nil, err
		}
		params.HasCursor, params.CursorCreatedAt, params.CursorID = true, core.Timestamptz(when), id
	}
	limit := int(params.RowLimit - 1)
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	rows, err := devicedb.New(s.Pool).ListManagedSecrets(ctx, params)
	if err != nil {
		return nil, core.MapErr(err)
	}
	response := &adminv1.ListSecretsResponse{Secrets: make([]*adminv1.SecretSummary, 0, min(len(rows), limit))}
	for i, row := range rows {
		if i == limit {
			last := rows[limit-1]
			created, ok := core.FiniteTime(last.CreatedAt)
			if !ok {
				return nil, core.MapErr(core.ErrInternalState)
			}
			if response.NextPageToken, err = core.EncodeCursor(created, last.ID); err != nil {
				return nil, core.MapErr(err)
			}
			break
		}
		item, err := secretSummary(row.ID, row.Purpose, row.SubjectBindingID, row.DisplayName, row.CurrentVersion, row.CreatedBy, row.CreatedAt, row.UpdatedAt, row.CreatorDisplayName)
		if err != nil {
			return nil, core.MapErr(err)
		}
		response.Secrets = append(response.Secrets, item)
	}
	return core.NoStore(response), nil
}

func (s *Service) GetSecret(ctx context.Context, req *connect.Request[adminv1.GetSecretRequest]) (*connect.Response[adminv1.GetSecretResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionManageSecrets)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_argument")
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
	summary, err := loadSecretSummary(ctx, q, id)
	if err != nil {
		return nil, core.MapErr(err)
	}
	rows, err := q.ListManagedSecretVersions(ctx, id)
	if err != nil {
		return nil, core.MapErr(err)
	}
	response := &adminv1.GetSecretResponse{Secret: summary, Versions: make([]*adminv1.SecretVersionSummary, 0, min(len(rows), secretVersionPage))}
	for _, row := range rows {
		created, ok := core.FiniteTime(row.CreatedAt)
		if !ok || row.Version <= 0 {
			return nil, core.MapErr(core.ErrInternalState)
		}
		response.Versions = append(response.Versions, &adminv1.SecretVersionSummary{Version: uint64(row.Version), CreatedAt: timestamppb.New(created), CreatedBy: row.CreatedBy.String(), CreatedByDisplayName: row.CreatorDisplayName, Reason: row.Reason})
	}
	if response.RevealApproval, err = s.CallerRevealApproval(ctx, q, actor, identity.PermissionRevealSecrets, uuid.Nil); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(response), nil
}

func (s *Service) RevealSecret(ctx context.Context, req *connect.Request[adminv1.RevealSecretRequest]) (*connect.Response[adminv1.RevealSecretResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionRevealSecrets)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) || req.Msg.GetVersion() >= 1<<62 {
		return nil, core.Invalid("invalid_secret_reveal")
	}
	if s.Identity == nil || s.Escrow == nil {
		return nil, errEscrowUnconfigured
	}
	if err := s.Identity.RequireRecentStepUp(ctx, 5*time.Minute); err != nil {
		return nil, rpcreason.Error(connect.CodePermissionDenied, "recent_step_up_required")
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	authorization, err := s.Identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionRevealSecrets)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	if err := s.RequireRevealApproval(ctx, authorization.Principal(), identity.PermissionRevealSecrets, uuid.Nil, req.Msg.GetApprovalId()); err != nil {
		return nil, err
	}
	consumption, err := s.PrepareActionApproval(ctx, actor, identity.PermissionRevealSecrets, req.Msg.GetApprovalId(), req.Msg)
	if err != nil {
		return nil, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.LockActionApproval(ctx, tx, consumption, authorization, identity.PermissionRevealSecrets); err != nil {
		return nil, core.ApprovalError(err)
	}
	// Secrets are deployment-global: only an unrestricted grant may reveal.
	if err := core.RequireUnrestrictedPrincipal(authorization.Principal(), identity.PermissionRevealSecrets); err != nil {
		return nil, err
	}
	id := uuid.MustParse(req.Msg.GetSecretId())
	q := devicedb.New(tx)
	stored, err := q.GetManagedSecretVersion(ctx, devicedb.GetManagedSecretVersionParams{SecretID: id, Version: int64(req.Msg.GetVersion())})
	if err != nil {
		return nil, core.MapErr(core.NotFoundIfMissing(err))
	}
	// Audit admission commits before plaintext is released, including every replay.
	if err := core.DispatchAudit(ctx, q, &actor.ID, "secret.reveal", id, req.Msg.GetReason()); err != nil {
		return nil, core.MapErr(err)
	}
	if err := s.LockActionApproval(ctx, tx, consumption, authorization, identity.PermissionRevealSecrets); err != nil {
		return nil, core.ApprovalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	plaintext, err := s.Escrow.OpenSecret(stored.BindingDocument, &escrow.SecretRecord{KeyID: stored.KeyID, WrappedKey: stored.WrappedKey, Ciphertext: stored.Ciphertext})
	if err != nil {
		return nil, errEscrowCustodyRejected
	}
	defer clear(plaintext)
	material := new(agentv1.SecretMaterial)
	if err := proto.Unmarshal(plaintext, material); err != nil {
		secretseal.Clear(material)
		return nil, errEscrowCustodyRejected
	}
	return core.NoStore(&adminv1.RevealSecretResponse{Material: material, Purpose: resourcev1.SecretPurpose(stored.Purpose)}), nil
}

// openManagedSecret loads the exact referenced version inside the caller's
// transaction and returns typed material. The caller clears it.
func (s *Service) OpenManagedSecret(ctx context.Context, q *devicedb.Queries, ref *resourcev1.SecretRef) (*agentv1.SecretMaterial, error) {
	if s.Escrow == nil || ref == nil || ref.GetVersion() == 0 || ref.GetVersion() >= 1<<62 {
		return nil, ErrSecretUnavailable
	}
	id, err := core.ParseUUID(ref.GetSecretId())
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	subject, err := core.ParseUUID(ref.GetSubjectBindingId())
	if err != nil {
		return nil, ErrSecretBindingMismatch
	}
	stored, err := q.GetManagedSecretVersion(ctx, devicedb.GetManagedSecretVersionParams{SecretID: id, Version: int64(ref.GetVersion())})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSecretUnavailable
	}
	if err != nil {
		return nil, err
	}
	if resourcev1.SecretPurpose(stored.Purpose) != ref.GetPurpose() || stored.SubjectBindingID != subject {
		return nil, ErrSecretBindingMismatch
	}
	plaintext, err := s.Escrow.OpenSecret(stored.BindingDocument, &escrow.SecretRecord{KeyID: stored.KeyID, WrappedKey: stored.WrappedKey, Ciphertext: stored.Ciphertext})
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	defer clear(plaintext)
	material := new(agentv1.SecretMaterial)
	if err := proto.Unmarshal(plaintext, material); err != nil || !secretMaterialMatches(ref.GetPurpose(), material) {
		secretseal.Clear(material)
		return nil, ErrSecretUnavailable
	}
	return material, nil
}
