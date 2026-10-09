package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/trust"
)

func (s *Service) AuthorizeServiceStart(ctx context.Context, req *connect.Request[devicev1.AuthorizeServiceStartRequest]) (*connect.Response[devicev1.AuthorizeServiceStartResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_service_start_request")
	}
	id, _ := uuid.Parse(req.Msg.GetActionId())
	captured, err := devicedb.New(s.pool).GetServiceAction(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	if captured.DeviceID != principal.DeviceID || captured.GenerationID != principal.GenerationID {
		return nil, rpcError(connect.CodePermissionDenied, "service_action_binding_rejected")
	}
	intent := new(agentv1.ServiceExecutionIntent)
	if err := proto.Unmarshal(captured.IntentDocument, intent); err != nil {
		return nil, mapErr(errInternalState)
	}
	challenge := new(agentv1.ServiceExecutionChallenge)
	if err := s.authority.Verify(ctx, req.Msg.GetChallengeProof(), challenge, 1, principal.PublicKey); err != nil {
		return nil, rpcError(connect.CodePermissionDenied, "service_challenge_rejected")
	}
	digest := sha256.Sum256(captured.IntentEnvelope)
	if challenge.GetDeploymentId() != intent.GetDeploymentId() || challenge.GetDeviceId() != intent.GetDeviceId() || challenge.GetEnrollmentGeneration() != intent.GetEnrollmentGeneration() || challenge.GetActionId() != intent.GetActionId() || challenge.GetDesiredRevision() != intent.GetDesiredRevision() || challenge.GetResourceSequence() != intent.GetResourceSequence() || challenge.GetRecoveryEpoch() != intent.GetRecoveryEpoch() || !bytes.Equal(challenge.GetIntentSha256(), digest[:]) {
		return nil, rpcError(connect.CodePermissionDenied, "service_challenge_binding_rejected")
	}
	var approval *identity.Authorization
	var authorizationErr error
	if len(captured.StartGrantEnvelope) == 0 {
		if s.signing == nil {
			return nil, rpcError(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
		}
		actor, err := uuid.Parse(intent.GetActorId())
		if err != nil {
			return nil, mapErr(errInternalState)
		}
		approval, authorizationErr = s.identity.AuthorizeFresh(ctx, actor, identity.PermissionAssignServices)
		if authorizationErr != nil && !assignmentAuthorizationDenied(authorizationErr) {
			return nil, executionError(authorizationErr)
		}
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if approval != nil {
		if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionAssignServices); err != nil {
			if !assignmentAuthorizationDenied(err) {
				return nil, executionError(err)
			}
			authorizationErr = err
		}
	}
	var snapshot *executionauthority.Snapshot
	var verifier *trust.ExecutionVerifier
	if approval != nil && authorizationErr == nil {
		snapshot, verifier, err = s.execution.CurrentInTransaction(ctx, tx)
		if err != nil {
			return nil, executionError(err)
		}
	}
	q := devicedb.New(tx)
	device, err := s.lockAuthority(ctx, q, principal)
	if err != nil {
		return nil, mapErr(err)
	}
	if uint64(device.generation.SessionEpoch) != req.Msg.GetSessionEpoch() {
		return nil, mapErr(errSessionFenced)
	}
	head, headErr := q.LockServiceAssignment(ctx, principal.GenerationID)
	if headErr != nil && !errors.Is(headErr, pgx.ErrNoRows) {
		return nil, mapErr(headErr)
	}
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
	if len(action.StartGrantEnvelope) != 0 {
		if !bytes.Equal(action.ChallengeProof, req.Msg.GetChallengeProof()) {
			return nil, rpcError(connect.CodeAlreadyExists, "service_start_conflict")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return noStore(&devicev1.AuthorizeServiceStartResponse{StartGrantEnvelope: action.StartGrantEnvelope}), nil
	}
	if action.ClosedAt.Valid {
		return nil, rpcError(connect.CodeFailedPrecondition, "service_action_closed")
	}
	rejectReason := ""
	switch {
	case head.ID != action.AssignmentID:
		rejectReason = "assignment_changed"
	case !now.Before(action.ExpiresAt.Time):
		rejectReason = "expired_unstarted"
	case authorizationErr != nil || approval.Version() != intent.GetAuthorizationVersion():
		rejectReason = "authority_changed"
	}
	if rejectReason != "" {
		if err := closeUnstartedServiceAction(ctx, q, action, rejectReason, now); err != nil {
			return nil, mapErr(err)
		}
		if rejectReason == "authority_changed" && head.ID == action.AssignmentID {
			if err := q.BlockServiceAssignment(ctx, devicedb.BlockServiceAssignmentParams{ID: head.ID, BlockedReason: "assignment_authority_changed"}); err != nil {
				return nil, mapErr(err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return nil, rpcError(connect.CodePermissionDenied, rejectReason)
	}
	if snapshot == nil || snapshot.Delegation == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	issued := challenge.GetIssuedAt().AsTime()
	if issued.After(now.Add(trust.MaxDeviceClockSkew)) || !now.Add(-trust.MaxDeviceClockSkew).Before(challenge.GetExpiresAt().AsTime()) {
		return nil, rpcError(connect.CodeFailedPrecondition, "device_clock_skew")
	}
	// The current authority and lease must be valid on server time, independently
	// of the bounded device-clock interval used for the challenge and grant.
	if _, err := verifier.VerifyServiceIntent(ctx, snapshot.Root, snapshot.Delegation, action.IntentEnvelope, now); err != nil {
		return nil, rpcError(connect.CodePermissionDenied, "service_start_authority_rejected")
	}
	expires := challenge.GetExpiresAt().AsTime()
	if limit := issued.Add(approval.ExpiresAt().Sub(now)); limit.Before(expires) {
		expires = limit
	}
	if limit := snapshot.Delegation.GetExpiresAt().AsTime(); limit.Before(expires) {
		expires = limit
	}
	if !expires.After(issued) {
		return nil, rpcError(connect.CodeFailedPrecondition, "service_start_window_empty")
	}
	grant := &agentv1.ServiceExecutionStartGrant{Challenge: challenge, ActorId: intent.GetActorId(), AuthorizationVersion: approval.Version(), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), NotBefore: challenge.GetIssuedAt(), ExpiresAt: timestamppb.New(expires)}
	envelope, err := s.authority.Sign(ctx, grant, s.signing.StartKey)
	if err != nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "execution_signing_rejected")
	}
	if _, err := verifier.VerifyServiceStart(ctx, snapshot.Root, snapshot.Delegation, envelope, intent, challenge, issued); err != nil {
		return nil, rpcError(connect.CodePermissionDenied, "service_start_authority_rejected")
	}
	if err := q.SetServiceGrant(ctx, devicedb.SetServiceGrantParams{ID: id, ChallengeProof: req.Msg.GetChallengeProof(), StartGrantEnvelope: envelope, StartAuthorizedAt: timestamptz(now)}); err != nil {
		return nil, mapErr(err)
	}
	if err := dispatchAudit(ctx, q, &head.ActorID, "service_action.start", id, "fresh_actor_authorization"); err != nil {
		return nil, mapErr(err)
	}
	if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionAssignServices); err != nil {
		return nil, executionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&devicev1.AuthorizeServiceStartResponse{StartGrantEnvelope: envelope}), nil
}
