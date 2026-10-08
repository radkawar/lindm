package device

import (
	"context"
	"crypto"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"lindm/internal/device/devicedb"
)

var (
	errIdempotencyConflict = rpcError(connect.CodeAlreadyExists, "idempotency_conflict")
	errGrantInvalid        = rpcError(connect.CodeUnauthenticated, "grant_invalid")
	errGrantExpired        = rpcError(connect.CodeUnauthenticated, "grant_expired")
	errGrantRevoked        = rpcError(connect.CodePermissionDenied, "grant_revoked")
	errGrantConsumed       = rpcError(connect.CodePermissionDenied, "grant_consumed")
	errDeviceRevoked       = rpcError(connect.CodePermissionDenied, "device_revoked")
	errCertificateRejected = rpcError(connect.CodePermissionDenied, "certificate_rejected")
	errGenerationMismatch  = rpcError(connect.CodeFailedPrecondition, "generation_mismatch")
	errInventoryConflict   = rpcError(connect.CodeAborted, "inventory_conflict")
	errRecoveryHold        = rpcError(connect.CodePermissionDenied, "recovery_hold")
	errSessionFenced       = rpcError(connect.CodeFailedPrecondition, "session_fenced")
	errAuthorityRejected   = rpcError(connect.CodePermissionDenied, "authority_rejected")
	errReceiptCapacity     = rpcError(connect.CodeResourceExhausted, "authority_receipt_capacity")
	errSnapshotExpired     = rpcError(connect.CodeFailedPrecondition, "snapshot_expired")
	errSnapshotIncomplete  = rpcError(connect.CodeFailedPrecondition, "snapshot_incomplete")
	errOpenUpload          = rpcError(connect.CodeFailedPrecondition, "open_upload")
	errRateLimited         = rpcError(connect.CodeResourceExhausted, "rate_limited")
	errInventoryBudget     = rpcError(connect.CodeResourceExhausted, "inventory_budget")
	errSnapshotCapacity    = rpcError(connect.CodeResourceExhausted, "snapshot_capacity")
	errPageExpired         = rpcError(connect.CodeFailedPrecondition, "page_expired")
	errSnapshotUnavailable = rpcError(connect.CodeFailedPrecondition, "snapshot_unavailable")
	errNotFound            = rpcError(connect.CodeNotFound, "not_found")
	errInternalState       = rpcError(connect.CodeInternal, "internal")
)

func insertAudit(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action, resourceID, reason string) error {
	return q.InsertAuditEvent(ctx, devicedb.InsertAuditEventParams{
		ID:         uuid.New(),
		ActorID:    actor,
		Action:     action,
		ResourceID: resourceID,
		Reason:     reason,
	})
}

func (s *Service) storeCertificate(ctx context.Context, q *devicedb.Queries, deviceID, generation uuid.UUID, pub crypto.PublicKey, now time.Time) (*issuedCert, error) {
	issued, err := issueCertificate(s.ca, s.caKey, pub, s.deploymentID, deviceID, generation, now)
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
		NotBefore:            timestamptz(issued.NotBefore),
		NotAfter:             timestamptz(issued.NotAfter),
		IssuedAt:             timestamptz(now),
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
	if row.State == stateRevoked {
		return false, nil
	}
	revoked, err := q.RevokeDeviceRecord(ctx, devicedb.RevokeDeviceRecordParams{
		RevokedAt:    timestamptz(now),
		RevokedBy:    &actor,
		RevokeReason: reason,
		ID:           deviceID,
	})
	if err != nil {
		return false, err
	}
	if revoked != 1 {
		return false, errInternalState
	}
	if err := q.RevokeDeviceCertificates(ctx, devicedb.RevokeDeviceCertificatesParams{
		RevokedAt:    timestamptz(now),
		RevokeReason: reason,
		DeviceID:     deviceID,
	}); err != nil {
		return false, err
	}
	if err := q.RevokeGenerations(ctx, deviceID); err != nil {
		return false, err
	}
	if err := insertAudit(ctx, q, &actor, actionDeviceRevoke, deviceID.String(), reason); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) beginAdminRequest(ctx context.Context, q *devicedb.Queries, actor uuid.UUID, method string, requestID uuid.UUID, digest []byte) (devicedb.GetAdminRequestForUpdateRow, bool, error) {
	if err := q.InsertAdminRequest(ctx, devicedb.InsertAdminRequestParams{
		ActorID:       actor,
		Method:        method,
		RequestID:     requestID,
		RequestDigest: digest,
		CreatedAt:     timestamptz(s.now()),
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
	if !digestEqual(row.RequestDigest, digest) {
		return devicedb.GetAdminRequestForUpdateRow{}, false, errIdempotencyConflict
	}
	if row.Completed {
		return row, false, nil
	}
	return row, true, nil
}

func completeAdmin(ctx context.Context, q *devicedb.Queries, actor uuid.UUID, method string, requestID, grantID, deviceID uuid.UUID, expires time.Time) error {
	return q.CompleteAdminRequest(ctx, devicedb.CompleteAdminRequestParams{
		GrantID:   grantID,
		DeviceID:  deviceID,
		ExpiresAt: timestamptz(expires),
		ActorID:   actor,
		Method:    method,
		RequestID: requestID,
	})
}

func notFoundIfMissing(err error) error {
	if err == pgx.ErrNoRows {
		return errNotFound
	}
	return err
}
