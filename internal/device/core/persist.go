// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"crypto"
	"encoding/json"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
)

var (
	ErrIdempotencyConflict = rpcreason.Error(connect.CodeAlreadyExists, "idempotency_conflict")
	errGrantInvalid        = rpcreason.Error(connect.CodeUnauthenticated, "grant_invalid")
	errGrantExpired        = rpcreason.Error(connect.CodeUnauthenticated, "grant_expired")
	errGrantRevoked        = rpcreason.Error(connect.CodePermissionDenied, "grant_revoked")
	errGrantConsumed       = rpcreason.Error(connect.CodePermissionDenied, "grant_consumed")
	ErrDeviceRevoked       = rpcreason.Error(connect.CodePermissionDenied, "device_revoked")
	ErrCertificateRejected = rpcreason.Error(connect.CodePermissionDenied, "certificate_rejected")
	ErrGenerationMismatch  = rpcreason.Error(connect.CodeFailedPrecondition, "generation_mismatch")
	ErrInventoryConflict   = rpcreason.Error(connect.CodeAborted, "inventory_conflict")
	errRecoveryHold        = rpcreason.Error(connect.CodePermissionDenied, "recovery_hold")
	ErrSessionFenced       = rpcreason.Error(connect.CodeFailedPrecondition, "session_fenced")
	ErrAuthorityRejected   = rpcreason.Error(connect.CodePermissionDenied, "authority_rejected")
	errReceiptCapacity     = rpcreason.Error(connect.CodeResourceExhausted, "authority_receipt_capacity")
	ErrSnapshotExpired     = rpcreason.Error(connect.CodeFailedPrecondition, "snapshot_expired")
	ErrSnapshotIncomplete  = rpcreason.Error(connect.CodeFailedPrecondition, "snapshot_incomplete")
	ErrOpenUpload          = rpcreason.Error(connect.CodeFailedPrecondition, "open_upload")
	ErrRateLimited         = rpcreason.Error(connect.CodeResourceExhausted, "rate_limited")
	ErrInventoryBudget     = rpcreason.Error(connect.CodeResourceExhausted, "inventory_budget")
	ErrSnapshotCapacity    = rpcreason.Error(connect.CodeResourceExhausted, "snapshot_capacity")
	ErrPageExpired         = rpcreason.Error(connect.CodeFailedPrecondition, "page_expired")
	ErrSnapshotUnavailable = rpcreason.Error(connect.CodeFailedPrecondition, "snapshot_unavailable")
	ErrNotFound            = rpcreason.Error(connect.CodeNotFound, "not_found")
	ErrInternalState       = rpcreason.Error(connect.CodeInternal, "internal")
)

func InsertAudit(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action auditkind.Kind, resourceID, reason string) error {
	return q.InsertAuditEvent(ctx, devicedb.InsertAuditEventParams{
		ID:         uuid.New(),
		ActorID:    actor,
		Action:     action.String(),
		ResourceID: resourceID,
		Reason:     reason,
	})
}

// auditDetails preserves separate machine-readable values without inventing an
// operator reason. Empty optional values are omitted.
func AuditDetails(pairs ...string) map[string]string {
	details := make(map[string]string, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			details[pairs[i]] = pairs[i+1]
		}
	}
	return details
}

func InsertDetailedAudit(ctx context.Context, q *devicedb.Queries, event devicedb.InsertAuditEventParams, details map[string]string) error {
	encoded, err := json.Marshal(details)
	if err != nil {
		return err
	}
	event.Details = encoded
	return q.InsertAuditEvent(ctx, event)
}

func DispatchSystemAudit(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action auditkind.Kind, id uuid.UUID, pairs ...string) error {
	return InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: actor, Action: action.String(), ResourceID: id.String(),
	}, AuditDetails(pairs...))
}

// DeviceAudit records an event about exactly one device and names it as the
// event's target, so the console's Device column and device filter find it.
// Device actions (resolved from device_actions) and the kinds in
// audit_direct_device_target are found without it.
func DeviceAudit(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action auditkind.Kind, resourceID string, device uuid.UUID, reason string, pairs ...string) error {
	return InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{
		ID: uuid.New(), ActorID: actor, Action: action.String(), ResourceID: resourceID, Reason: reason, TargetDeviceID: &device,
	}, AuditDetails(pairs...))
}

func (s *Service) storeCertificate(ctx context.Context, q *devicedb.Queries, deviceID, generation uuid.UUID, pub crypto.PublicKey, now time.Time) (*issuedCert, error) {
	issued, err := IssueCertificate(s.CA, s.CAKey, pub, s.DeploymentID, deviceID, generation, now)
	if err != nil {
		return nil, err
	}
	issued.ID = uuid.New()
	err = q.InsertDeviceCertificate(ctx, devicedb.InsertDeviceCertificateParams{
		ID:                   issued.ID,
		DeviceID:             deviceID,
		GenerationID:         generation,
		Serial:               issued.Serial,
		Fingerprint:          issued.Fingerprint,
		PublicKeyFingerprint: issued.PublicKeyFingerprint,
		Pem:                  string(issued.PEM),
		NotBefore:            Timestamptz(issued.NotBefore),
		NotAfter:             Timestamptz(issued.NotAfter),
		IssuedAt:             Timestamptz(now),
	})
	if err != nil {
		return nil, err
	}
	return issued, nil
}

func (s *Service) revokeLockedDevice(ctx context.Context, q *devicedb.Queries, deviceID, actor uuid.UUID, reason string, now time.Time) (bool, error) {
	row, err := q.GetDeviceForUpdate(ctx, deviceID)
	if err != nil {
		return false, err
	}
	if row.State == StateRevoked {
		return false, nil
	}
	revoked, err := q.RevokeDeviceRecord(ctx, devicedb.RevokeDeviceRecordParams{
		RevokedAt:    Timestamptz(now),
		RevokedBy:    &actor,
		RevokeReason: reason,
		ID:           deviceID,
	})
	if err != nil {
		return false, err
	}
	if revoked != 1 {
		return false, ErrInternalState
	}
	if err := q.RevokeDeviceCertificates(ctx, devicedb.RevokeDeviceCertificatesParams{
		RevokedAt:    Timestamptz(now),
		RevokeReason: reason,
		DeviceID:     deviceID,
	}); err != nil {
		return false, err
	}
	if err := q.RevokeGenerations(ctx, deviceID); err != nil {
		return false, err
	}
	if err := InsertAudit(ctx, q, &actor, auditkind.DeviceRevoke, deviceID.String(), reason); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) BeginAdminRequest(ctx context.Context, q *devicedb.Queries, actor uuid.UUID, method string, requestID uuid.UUID, digest []byte) (devicedb.GetAdminRequestForUpdateRow, bool, error) {
	if err := q.InsertAdminRequest(ctx, devicedb.InsertAdminRequestParams{
		ActorID:       actor,
		Method:        method,
		RequestID:     requestID,
		RequestDigest: digest,
		CreatedAt:     Timestamptz(s.Now()),
	}); err != nil {
		return devicedb.GetAdminRequestForUpdateRow{}, false, err
	}
	row, err := q.GetAdminRequestForUpdate(ctx, devicedb.GetAdminRequestForUpdateParams{
		ActorID:   actor,
		Method:    method,
		RequestID: requestID,
	})
	if err != nil {
		return devicedb.GetAdminRequestForUpdateRow{}, false, err
	}
	if !DigestEqual(row.RequestDigest, digest) {
		return devicedb.GetAdminRequestForUpdateRow{}, false, ErrIdempotencyConflict
	}
	if row.Completed {
		return row, false, nil
	}
	return row, true, nil
}

func CompleteAdmin(ctx context.Context, q *devicedb.Queries, actor uuid.UUID, method string, requestID, grantID, deviceID uuid.UUID, expires time.Time) error {
	return q.CompleteAdminRequest(ctx, devicedb.CompleteAdminRequestParams{
		GrantID:   grantID,
		DeviceID:  deviceID,
		ExpiresAt: Timestamptz(expires),
		ActorID:   actor,
		Method:    method,
		RequestID: requestID,
	})
}

func NotFoundIfMissing(err error) error {
	if err == pgx.ErrNoRows {
		return ErrNotFound
	}
	return err
}

func DispatchAudit(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action auditkind.Kind, id uuid.UUID, reason string) error {
	return q.InsertAuditEvent(ctx, devicedb.InsertAuditEventParams{ID: uuid.New(), ActorID: actor, Action: action.String(), ResourceID: id.String(), Reason: reason})
}
