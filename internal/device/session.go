package device

import (
	"context"
	"crypto/sha256"
	"math"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
)

func (s *Service) AcquireSession(ctx context.Context, req *connect.Request[devicev1.AcquireSessionRequest]) (*connect.Response[devicev1.AcquireSessionResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req.Msg == nil || !validAuthorityProof(req.Msg.GetAuthorityProof()) {
		return nil, invalid("authority_proof")
	}
	claim := new(agentv1.SessionAcquisition)
	if err := s.authority.Verify(ctx, req.Msg.GetAuthorityProof(), claim, 1, principal.PublicKey); err != nil {
		return nil, errAuthorityRejected
	}
	requestID, err := parseUUID(claim.GetRequestId())
	if err != nil || !s.authorityBinding(claim.GetDeploymentId(), claim.GetDeviceId(), claim.GetEnrollmentGeneration(), principal) || claim.GetPredecessorEpoch() > math.MaxInt64 {
		return nil, errAuthorityRejected
	}
	if _, err := parseUUID(claim.GetIncarnation()); err != nil {
		return nil, errAuthorityRejected
	}
	if _, err := parseUUID(claim.GetBootId()); err != nil {
		return nil, errAuthorityRejected
	}
	digest := sha256.Sum256(req.Msg.GetAuthorityProof())
	var response *devicev1.AcquireSessionResponse
	var held bool
	err = s.within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		authority, err := s.lockAuthority(ctx, q, principal)
		if err != nil {
			return err
		}
		receipt, receiptErr := q.GetSessionReceipt(ctx, devicedb.GetSessionReceiptParams{GenerationID: principal.GenerationID, RequestID: requestID})
		if receiptErr != nil && receiptErr != pgx.ErrNoRows {
			return receiptErr
		}
		if receiptErr == nil && digestEqual(receipt.RequestDigest, digest[:]) {
			acceptedAt, ok := finiteTime(receipt.AcceptedAt)
			if !ok {
				return errInternalState
			}
			response = &devicev1.AcquireSessionResponse{SessionEpoch: uint64(receipt.SessionEpoch), HostSequence: uint64(receipt.HostSequence), PackageSequence: uint64(receipt.PackageSequence), ServerTime: timestamppb.New(acceptedAt)}
			return nil
		}
		// DSSE's outer JSON encoding is not signed. A changed encoding of an
		// existing request must conflict, not let the transport manufacture a
		// second protected successor claim and place the device in clone hold.
		if receiptErr == nil {
			return errIdempotencyConflict
		}
		predecessor := int64(claim.GetPredecessorEpoch())
		current := authority.generation.SessionEpoch
		if predecessor < current {
			// The denial is returned only after commit. Returning it from this
			// transaction would roll back the durable ambiguity fence and audit.
			if err := q.HoldDevice(ctx, principal.DeviceID); err != nil {
				return err
			}
			if err := q.HoldGeneration(ctx, principal.GenerationID); err != nil {
				return err
			}
			if err := insertAudit(ctx, q, nil, actionDeviceRecoveryHold, principal.DeviceID.String(), "consumed_session_predecessor"); err != nil {
				return err
			}
			held = true
			return nil
		}
		if predecessor > current {
			return rpcError(connect.CodeFailedPrecondition, "session_predecessor")
		}
		if current >= maxSessionReceipts {
			return errReceiptCapacity
		}
		next := current + 1
		if err := q.InsertSessionReceipt(ctx, devicedb.InsertSessionReceiptParams{
			GenerationID: principal.GenerationID, RequestID: requestID, RequestDigest: digest[:],
			SessionEpoch: next, HostSequence: authority.generation.HostSequence,
			PackageSequence: authority.generation.PackageSequence, AcceptedAt: timestamptz(authority.now),
		}); err != nil {
			return err
		}
		if err := q.AdvanceSessionEpoch(ctx, devicedb.AdvanceSessionEpochParams{SessionEpoch: next, ID: principal.GenerationID}); err != nil {
			return err
		}
		if err := q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: timestamptz(authority.now), ID: principal.DeviceID}); err != nil {
			return err
		}
		response = &devicev1.AcquireSessionResponse{SessionEpoch: uint64(next), HostSequence: uint64(authority.generation.HostSequence), PackageSequence: uint64(authority.generation.PackageSequence), ServerTime: timestamppb.New(authority.now)}
		return nil
	})
	if err != nil {
		return nil, mapErr(err)
	}
	if held {
		return nil, errRecoveryHold
	}
	return noStore(response), nil
}

func (s *Service) GetSyncState(ctx context.Context, req *connect.Request[devicev1.GetSyncStateRequest]) (*connect.Response[devicev1.GetSyncStateResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req.Msg == nil || !validSessionEpoch(req.Msg.GetSessionEpoch()) {
		return nil, invalid("session_epoch")
	}
	var response *devicev1.GetSyncStateResponse
	err := s.within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		authority, err := s.lockAuthority(ctx, q, principal)
		if err != nil {
			return err
		}
		if uint64(authority.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
			return errSessionFenced
		}
		if err := q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{LastSeenAt: timestamptz(authority.now), ID: principal.DeviceID}); err != nil {
			return err
		}
		response = &devicev1.GetSyncStateResponse{SessionEpoch: req.Msg.GetSessionEpoch(), HostSequence: uint64(authority.generation.HostSequence), PackageSequence: uint64(authority.generation.PackageSequence), ServerTime: timestamppb.New(authority.now)}
		return nil
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return noStore(response), nil
}

func (s *Service) authorityBinding(deployment, deviceID, generation string, principal devicePrincipal) bool {
	// UUID parsers accept equivalent noncanonical encodings, but signed identity
	// authority uses only the canonical strings delivered at enrollment.
	return deployment == s.deploymentID.String() && deviceID == principal.DeviceID.String() && generation == principal.GenerationID.String()
}
