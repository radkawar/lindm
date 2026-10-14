// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"crypto/sha256"
	"math"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/auditkind"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
)

func (s *Service) AcquireSession(ctx context.Context, req *connect.Request[devicev1.AcquireSessionRequest]) (*connect.Response[devicev1.AcquireSessionResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	principal, ok := DevicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req.Msg == nil || !ValidAuthorityProof(req.Msg.GetAuthorityProof()) {
		return nil, Invalid("authority_proof")
	}
	claim := new(agentv1.SessionAcquisition)
	if err := s.Authority.Verify(ctx, req.Msg.GetAuthorityProof(), claim, 1, principal.PublicKey); err != nil {
		return nil, ErrAuthorityRejected
	}
	requestID, err := ParseUUID(claim.GetRequestId())
	if err != nil || !s.AuthorityBinding(claim.GetDeploymentId(), claim.GetDeviceId(), claim.GetEnrollmentGeneration(), principal) || claim.GetPredecessorEpoch() > math.MaxInt64 {
		return nil, ErrAuthorityRejected
	}
	if _, err := ParseUUID(claim.GetIncarnation()); err != nil {
		return nil, ErrAuthorityRejected
	}
	bootID, err := ParseUUID(claim.GetBootId())
	if err != nil {
		return nil, ErrAuthorityRejected
	}
	installationID, err := ParseUUID(claim.GetInstallationId())
	if err != nil {
		return nil, ErrAuthorityRejected
	}
	digest := sha256.Sum256(req.Msg.GetAuthorityProof())
	var response *devicev1.AcquireSessionResponse
	var held bool
	err = s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		authority, err := s.LockAuthority(ctx, q, principal)
		if err != nil {
			return err
		}
		receipt, receiptErr := q.GetSessionReceipt(ctx, devicedb.GetSessionReceiptParams{GenerationID: principal.GenerationID, RequestID: requestID})
		if receiptErr != nil && receiptErr != pgx.ErrNoRows {
			return receiptErr
		}
		if receiptErr == nil && DigestEqual(receipt.RequestDigest, digest[:]) {
			acceptedAt, ok := FiniteTime(receipt.AcceptedAt)
			if !ok {
				return ErrInternalState
			}
			response = &devicev1.AcquireSessionResponse{SessionEpoch: uint64(receipt.SessionEpoch), HostSequence: uint64(receipt.HostSequence), PackageSequence: uint64(receipt.PackageSequence), ServerTime: timestamppb.New(acceptedAt)}
			return nil
		}
		installation, installationErr := q.GetEnrollmentInstallation(ctx, principal.GenerationID)
		if installationErr != nil && installationErr != pgx.ErrNoRows {
			return installationErr
		}
		if installationErr == nil && installation.InstallationID != installationID {
			if err := holdClonedIdentity(ctx, q, principal, "conflicting_installation_identity"); err != nil {
				return err
			}
			held = true
			return nil
		}
		// DSSE's outer JSON encoding is not signed. A changed encoding of an
		// existing request must conflict, not let the transport manufacture a
		// second protected successor claim and place the device in clone hold.
		if receiptErr == nil {
			return ErrIdempotencyConflict
		}
		predecessor := int64(claim.GetPredecessorEpoch())
		current := authority.Generation.SessionEpoch
		if predecessor < current {
			// The denial is returned only after commit. Returning it from this
			// transaction would roll back the durable ambiguity fence and audit.
			if err := holdClonedIdentity(ctx, q, principal, "consumed_session_predecessor"); err != nil {
				return err
			}
			held = true
			return nil
		}
		if predecessor > current {
			return rpcreason.Error(connect.CodeFailedPrecondition, "session_predecessor")
		}
		if current >= MaxSessionReceipts {
			return errReceiptCapacity
		}
		bound, err := q.PutEnrollmentSessionInstallation(ctx, devicedb.PutEnrollmentSessionInstallationParams{
			GenerationID: principal.GenerationID, InstallationID: installationID, BootID: &bootID,
		})
		if err != nil {
			return err
		}
		if bound != 1 {
			return ErrInternalState
		}
		next := current + 1
		if err := q.InsertSessionReceipt(ctx, devicedb.InsertSessionReceiptParams{
			GenerationID: principal.GenerationID, RequestID: requestID, RequestDigest: digest[:],
			SessionEpoch: next, HostSequence: authority.Generation.HostSequence,
			PackageSequence: authority.Generation.PackageSequence, AcceptedAt: Timestamptz(authority.Now),
		}); err != nil {
			return err
		}
		if err := q.AdvanceSessionEpoch(ctx, devicedb.AdvanceSessionEpochParams{SessionEpoch: next, ID: principal.GenerationID}); err != nil {
			return err
		}
		if err := q.PutDeviceReleaseReport(ctx, devicedb.PutDeviceReleaseReportParams{
			GenerationID: principal.GenerationID, SessionEpoch: next,
			AgentRelease: claim.GetAgentRelease(), ProtocolVersion: int32(claim.GetAgentProtocolVersion()),
			ReportedAt: Timestamptz(authority.Now),
		}); err != nil {
			return err
		}
		if err := q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: Timestamptz(authority.Now), ID: principal.DeviceID}); err != nil {
			return err
		}
		response = &devicev1.AcquireSessionResponse{SessionEpoch: uint64(next), HostSequence: uint64(authority.Generation.HostSequence), PackageSequence: uint64(authority.Generation.PackageSequence), ServerTime: timestamppb.New(authority.Now)}
		return nil
	})
	if err != nil {
		return nil, MapErr(err)
	}
	if held {
		return nil, errRecoveryHold
	}
	return NoStore(response), nil
}

func (s *Service) GetSyncState(ctx context.Context, req *connect.Request[devicev1.GetSyncStateRequest]) (*connect.Response[devicev1.GetSyncStateResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	principal, ok := DevicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req.Msg == nil || !ValidSessionEpoch(req.Msg.GetSessionEpoch()) {
		return nil, Invalid("session_epoch")
	}
	if err := s.Rules.Validate(req.Msg); err != nil {
		return nil, Invalid("agent_update")
	}
	var response *devicev1.GetSyncStateResponse
	err := s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		authority, err := s.LockAuthority(ctx, q, principal)
		if err != nil {
			return err
		}
		if uint64(authority.Generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
			return ErrSessionFenced
		}
		if err := recordAgentUpdate(ctx, q, principal, req.Msg.GetSessionEpoch(), req.Msg.GetAgentUpdate(), authority.Now); err != nil {
			return err
		}
		if err := q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: Timestamptz(authority.Now), ID: principal.DeviceID}); err != nil {
			return err
		}
		response = &devicev1.GetSyncStateResponse{SessionEpoch: req.Msg.GetSessionEpoch(), HostSequence: uint64(authority.Generation.HostSequence), PackageSequence: uint64(authority.Generation.PackageSequence), ServerTime: timestamppb.New(authority.Now)}
		return nil
	})
	if err != nil {
		return nil, MapErr(err)
	}
	return NoStore(response), nil
}

func (s *Service) AuthorityBinding(deployment, deviceID, generation string, principal DevicePrincipal) bool {
	// UUID parsers accept equivalent noncanonical encodings, but signed identity
	// authority uses only the canonical strings delivered at enrollment.
	return deployment == s.DeploymentID.String() && deviceID == principal.DeviceID.String() && generation == principal.GenerationID.String()
}

func holdClonedIdentity(ctx context.Context, q *devicedb.Queries, principal DevicePrincipal, reason string) error {
	if err := q.HoldDevice(ctx, principal.DeviceID); err != nil {
		return err
	}
	if err := q.HoldGeneration(ctx, principal.GenerationID); err != nil {
		return err
	}
	return InsertDetailedAudit(ctx, q, devicedb.InsertAuditEventParams{ID: uuid.New(), Action: auditkind.DeviceRecoveryHold.String(), ResourceID: principal.DeviceID.String(), TargetDeviceID: &principal.DeviceID}, AuditDetails("cause", reason))
}
