package device

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/trust"
)

func (s *Service) ReportServiceResult(ctx context.Context, req *connect.Request[devicev1.ReportServiceResultRequest]) (*connect.Response[devicev1.ReportServiceResultResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_service_result_request")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	device, err := s.lockAuthority(ctx, q, principal)
	if err != nil {
		return nil, mapErr(err)
	}
	if uint64(device.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, mapErr(errSessionFenced)
	}
	if _, err := q.LockServiceAssignment(ctx, principal.GenerationID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, mapErr(err)
	}
	id, _ := uuid.Parse(req.Msg.GetActionId())
	action, err := q.LockServiceAction(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, mapErr(err)
	}
	if !enrollmentIssuanceResumable(device.certificate, now) {
		return nil, mapErr(errCertificateRejected)
	}
	if action.DeviceID != principal.DeviceID || action.GenerationID != principal.GenerationID {
		return nil, rpcError(connect.CodePermissionDenied, "service_action_binding_rejected")
	}
	block, rest := pem.Decode(req.Msg.GetCertificatePem())
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, mapErr(errCertificateRejected)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, mapErr(errCertificateRejected)
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	certificate, err := q.GetCertificateByFingerprint(ctx, fingerprint[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, mapErr(errCertificateRejected)
		}
		return nil, mapErr(err)
	}
	// The CA signature alone is insufficient: only a registered, non-revoked
	// certificate for this generation can attest, including during renewal overlap.
	if certificate.DeviceID != principal.DeviceID || certificate.GenerationID != principal.GenerationID || now.Before(certificate.NotBefore.Time) || !now.Before(certificate.NotAfter.Time) || (certificate.Status != "active" && (certificate.Status != "overlapping" || !certificate.OverlapUntil.Valid || !now.Before(certificate.OverlapUntil.Time))) {
		return nil, mapErr(errCertificateRejected)
	}
	if bytes.Equal(action.AttestationEnvelope, req.Msg.GetAttestationEnvelope()) && bytes.Equal(action.AttestationCertificate, req.Msg.GetCertificatePem()) {
		// This exact evidence was already cryptographically admitted. Consumed nonce
		// and subsequent wall-clock expiry cannot make a lost response non-idempotent.
		public, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, mapErr(errCertificateRejected)
		}
		accepted := new(agentv1.ServiceExecutionAttestation)
		if err := s.authority.Verify(ctx, action.AttestationEnvelope, accepted, 1, public); err != nil || accepted.GetSessionEpoch() != req.Msg.GetSessionEpoch() {
			return nil, rpcError(connect.CodePermissionDenied, "service_result_rejected")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return noStore(&devicev1.ReportServiceResultResponse{Closed: action.ClosedAt.Valid}), nil
	}
	if len(action.ResultNonce) != 32 || !action.NonceExpiresAt.Valid || !now.Before(action.NonceExpiresAt.Time) {
		return nil, rpcError(connect.CodePermissionDenied, "service_result_nonce_rejected")
	}
	binding := &trust.ServiceAttestationBinding{DeploymentID: s.deploymentID, DeviceID: principal.DeviceID, EnrollmentGeneration: principal.GenerationID, SessionEpoch: req.Msg.GetSessionEpoch(), ActionID: id, IntentSHA256: sha256.Sum256(action.IntentEnvelope)}
	copy(binding.Nonce[:], action.ResultNonce)
	attestation, err := s.authority.VerifyServiceAttestation(ctx, req.Msg.GetAttestationEnvelope(), req.Msg.GetCertificatePem(), s.ca, binding, now, trust.MaxDeviceClockSkew)
	if errors.Is(err, trust.ErrDeviceClockSkew) {
		return nil, rpcError(connect.CodeFailedPrecondition, "device_clock_skew")
	}
	if err != nil {
		return nil, rpcError(connect.CodePermissionDenied, "service_result_rejected")
	}
	previous, err := serviceActionRevision(action)
	if err != nil {
		return nil, mapErr(err)
	}
	if attestation.GetActionRevision() <= previous {
		return nil, rpcError(connect.CodeAlreadyExists, "service_result_conflict")
	}
	status := attestation.GetStatus()
	terminal := status.GetState() >= agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED
	if action.ClosedAt.Valid && !terminal {
		return nil, rpcError(connect.CodeAlreadyExists, "service_result_conflict")
	}
	encoded, err := proto.Marshal(status)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := q.SetServiceResult(ctx, devicedb.SetServiceResultParams{ID: id, ActionRevision: pgtype.Numeric{Int: new(big.Int).SetUint64(attestation.GetActionRevision()), Valid: true}, AttestationEnvelope: req.Msg.GetAttestationEnvelope(), AttestationCertificate: req.Msg.GetCertificatePem(), StatusDocument: encoded, AttestedAt: timestamptz(attestation.GetIssuedAt().AsTime()), ReceivedAt: timestamptz(now)}); err != nil {
		return nil, mapErr(err)
	}
	disposition, reason := int16(2), ""
	if terminal {
		if err := q.CloseServiceAction(ctx, devicedb.CloseServiceActionParams{ID: id, ClosedAt: timestamptz(now), ClosedReason: "result"}); err != nil {
			return nil, mapErr(err)
		}
		switch {
		case status.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUCCEEDED:
			disposition = 3
		case (status.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_EXPIRED || status.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_SUPERSEDED) && status.GetStartedAt() == nil:
			disposition, reason = 1, "no_effect"
		default:
			disposition, reason = 4, "execution_failed"
			if status.GetState() == agentv1.ServiceExecutionState_SERVICE_EXECUTION_STATE_OUTCOME_UNKNOWN {
				reason = "outcome_unknown"
			}
		}
	}
	// A late report for an older action must not overwrite a newer lease's
	// disposition, even though the signed evidence remains retained and audited.
	latest, err := q.LatestServiceAction(ctx, devicedb.LatestServiceActionParams{AssignmentID: action.AssignmentID, ResourceID: action.ResourceID})
	if err != nil {
		return nil, mapErr(err)
	}
	if latest.ID == action.ID {
		if err := q.SetServiceResourceDisposition(ctx, devicedb.SetServiceResourceDispositionParams{AssignmentID: action.AssignmentID, ResourceID: action.ResourceID, Disposition: disposition, Reason: reason}); err != nil {
			return nil, mapErr(err)
		}
	}
	if err := dispatchAudit(ctx, q, nil, "service_action.result", id, "verified_device_attestation"); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&devicev1.ReportServiceResultResponse{Closed: terminal || action.ClosedAt.Valid}), nil
}
