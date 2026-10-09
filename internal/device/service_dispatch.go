package device

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/trust"
)

func (s *Service) GetServiceWork(ctx context.Context, req *connect.Request[devicev1.GetServiceWorkRequest]) (*connect.Response[devicev1.GetServiceWorkResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	principal, ok := devicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcError(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_service_work_request")
	}
	work, choice, err := s.getServiceWork(ctx, principal, req.Msg.GetSessionEpoch(), nil, nil, nil)
	if err != nil {
		return nil, executionError(err)
	}
	if choice != nil {
		if s.identity == nil {
			return nil, rpcError(connect.CodeFailedPrecondition, "service_authorization_unavailable")
		}
		approval, authorizationErr := s.identity.AuthorizeFresh(ctx, choice.ActorID, identity.PermissionAssignServices)
		if authorizationErr != nil && !assignmentAuthorizationDenied(authorizationErr) {
			return nil, executionError(authorizationErr)
		}
		work, _, err = s.getServiceWork(ctx, principal, req.Msg.GetSessionEpoch(), choice, approval, authorizationErr)
		if err != nil {
			return nil, executionError(err)
		}
	}
	return noStore(&devicev1.GetServiceWorkResponse{Work: work}), nil
}

// The first transaction either replays work or captures the exact mint choice.
// Only after it ends is the directory consulted. The second transaction fences
// that approval before authority/device/head/action locks and rechecks the choice.
func (s *Service) getServiceWork(ctx context.Context, principal devicePrincipal, epoch uint64, choice *devicedb.ServiceAssignment, approval *identity.Authorization, authorizationErr error) (*devicev1.ServiceWork, *devicedb.ServiceAssignment, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if approval != nil {
		if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionAssignServices); err != nil {
			if !assignmentAuthorizationDenied(err) {
				return nil, nil, err
			}
			authorizationErr = err
		}
	}
	var snapshot *executionauthority.Snapshot
	var verifier *trust.ExecutionVerifier
	if choice != nil && authorizationErr == nil {
		if s.signing == nil {
			return nil, nil, rpcError(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
		}
		snapshot, verifier, err = s.execution.CurrentInTransaction(ctx, tx)
		if err != nil {
			return nil, nil, err
		}
	}
	q := devicedb.New(tx)
	device, err := s.lockAuthority(ctx, q, principal)
	if err != nil {
		return nil, nil, err
	}
	if uint64(device.generation.SessionEpoch) != epoch {
		return nil, nil, errSessionFenced
	}
	head, headErr := q.LockServiceAssignment(ctx, principal.GenerationID)
	if headErr != nil && !errors.Is(headErr, pgx.ErrNoRows) {
		return nil, nil, headErr
	}
	action, actionErr := q.GetOpenServiceAction(ctx, principal.DeviceID)
	if actionErr != nil && !errors.Is(actionErr, pgx.ErrNoRows) {
		return nil, nil, actionErr
	}
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	if !enrollmentIssuanceResumable(device.certificate, now) {
		return nil, nil, errCertificateRejected
	}
	if actionErr == nil && len(action.StartGrantEnvelope) == 0 {
		reason := ""
		if action.AssignmentID != head.ID {
			reason = "assignment_changed"
		} else if !now.Before(action.ExpiresAt.Time) {
			reason = "expired_unstarted"
		}
		if reason != "" {
			if err := closeUnstartedServiceAction(ctx, q, action, reason, now); err != nil {
				return nil, nil, err
			}
			actionErr = pgx.ErrNoRows
		}
	}
	if actionErr == nil {
		// Issued start authority may have caused an effect. Expiry, reassignment and
		// actor revocation never manufacture a replacement for an unreported effect.
		if action.GenerationID != principal.GenerationID {
			return nil, nil, rpcError(connect.CodeFailedPrecondition, "service_action_generation_pending")
		}
		work, err := issueServiceNonce(ctx, q, action, now)
		if err != nil {
			return nil, nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, nil, err
		}
		return work, nil, nil
	}
	if errors.Is(headErr, pgx.ErrNoRows) || head.RevisionID == nil || head.BlockedReason != "" {
		return nil, nil, tx.Commit(ctx)
	}
	resources, err := q.ListServiceResources(ctx, head.ID)
	if err != nil {
		return nil, nil, err
	}
	candidate, err := eligibleServiceResource(resources)
	if err != nil {
		return nil, nil, err
	}
	if candidate == nil {
		return nil, nil, tx.Commit(ctx)
	}
	if choice == nil {
		if s.signing == nil {
			return nil, nil, rpcError(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, nil, err
		}
		return nil, &head, nil
	}
	if choice.ID != head.ID {
		return nil, nil, rpcError(connect.CodeAborted, "service_assignment_conflict")
	}
	if authorizationErr != nil || approval.Version() != uint64(head.AuthorizationVersion) {
		if err := q.BlockServiceAssignment(ctx, devicedb.BlockServiceAssignmentParams{ID: head.ID, BlockedReason: "assignment_authority_changed"}); err != nil {
			return nil, nil, err
		}
		return nil, nil, tx.Commit(ctx)
	}
	if snapshot == nil || snapshot.Delegation == nil {
		return nil, nil, rpcError(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	capacity, err := q.ServiceDispatchCapacity(ctx, principal.GenerationID)
	if err != nil {
		return nil, nil, err
	}
	if capacity.Actions >= 262144 {
		return nil, nil, rpcError(connect.CodeResourceExhausted, "service_action_capacity")
	}
	sequence, err := q.NextServiceSequence(ctx, devicedb.NextServiceSequenceParams{GenerationID: principal.GenerationID, UnitName: candidate.GetDesired().GetUnit()})
	if err != nil {
		return nil, nil, err
	}
	notBefore := now.Add(-trust.MaxDeviceClockSkew)
	expires := notBefore.Add(12 * time.Minute)
	if snapshot.Delegation.GetExpiresAt().AsTime().Before(expires) {
		expires = snapshot.Delegation.GetExpiresAt().AsTime()
	}
	id := uuid.New()
	intent := &agentv1.ServiceExecutionIntent{DeploymentId: s.deploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(), ActionId: id.String(), DesiredRevision: head.ID.String(), ActorId: head.ActorID.String(), ResourceSequence: uint64(sequence), RecoveryEpoch: snapshot.Delegation.GetMinimumRecoveryEpoch(), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), AuthorizationVersion: approval.Version(), NotBefore: timestamppb.New(notBefore), ExpiresAt: timestamppb.New(expires), Desired: candidate.GetDesired()}
	envelope, err := s.authority.Sign(ctx, intent, s.signing.PlanKey)
	if err != nil {
		return nil, nil, rpcError(connect.CodeFailedPrecondition, "execution_signing_rejected")
	}
	if _, err := verifier.VerifyServiceIntent(ctx, snapshot.Root, snapshot.Delegation, envelope, now); err != nil {
		return nil, nil, rpcError(connect.CodeFailedPrecondition, "execution_signing_rejected")
	}
	document, err := proto.Marshal(intent)
	if err != nil {
		return nil, nil, err
	}
	resourceID, _ := uuid.Parse(candidate.GetResourceId())
	if err := q.InsertServiceAction(ctx, devicedb.InsertServiceActionParams{ID: id, DeviceID: principal.DeviceID, GenerationID: principal.GenerationID, AssignmentID: head.ID, ResourceID: resourceID, ResourceSequence: sequence, IntentEnvelope: envelope, IntentDocument: document, IssuedAt: timestamptz(now), ExpiresAt: timestamptz(expires)}); err != nil {
		return nil, nil, err
	}
	if err := q.SetServiceResourceDisposition(ctx, devicedb.SetServiceResourceDispositionParams{AssignmentID: head.ID, ResourceID: resourceID, Disposition: 2}); err != nil {
		return nil, nil, err
	}
	if err := dispatchAudit(ctx, q, &head.ActorID, "service_action.mint", id, "service_assignment"); err != nil {
		return nil, nil, err
	}
	action, err = q.LockServiceAction(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	work, err := issueServiceNonce(ctx, q, action, now)
	if err != nil {
		return nil, nil, err
	}
	if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionAssignServices); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return work, nil, nil
}

func eligibleServiceResource(rows []devicedb.ServiceAssignmentResource) (*policyv1.ServiceProfileResource, error) {
	dispositions := make(map[string]int16, len(rows))
	for _, row := range rows {
		dispositions[row.ResourceID.String()] = row.Disposition
	}
	for _, row := range rows {
		if row.Disposition != 1 {
			continue
		}
		resource := new(policyv1.ServiceProfileResource)
		if err := proto.Unmarshal(row.Document, resource); err != nil {
			return nil, errInternalState
		}
		eligible := true
		for _, dependency := range resource.GetDependsOn() {
			if dispositions[dependency] != 3 {
				eligible = false
				break
			}
		}
		if eligible {
			return resource, nil
		}
	}
	return nil, nil
}

func closeUnstartedServiceAction(ctx context.Context, q *devicedb.Queries, action devicedb.ServiceAction, reason string, now time.Time) error {
	if len(action.StartGrantEnvelope) != 0 {
		return errInternalState
	}
	if err := q.CloseServiceAction(ctx, devicedb.CloseServiceActionParams{ID: action.ID, ClosedAt: timestamptz(now), ClosedReason: reason}); err != nil {
		return err
	}
	return q.SetServiceResourceDisposition(ctx, devicedb.SetServiceResourceDispositionParams{AssignmentID: action.AssignmentID, ResourceID: action.ResourceID, Disposition: 1, Reason: reason})
}

func issueServiceNonce(ctx context.Context, q *devicedb.Queries, action devicedb.ServiceAction, now time.Time) (*devicev1.ServiceWork, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	expires := now.Add(time.Minute)
	if err := q.SetServiceNonce(ctx, devicedb.SetServiceNonceParams{ID: action.ID, ResultNonce: nonce[:], NonceExpiresAt: timestamptz(expires)}); err != nil {
		return nil, err
	}
	return &devicev1.ServiceWork{ActionId: action.ID.String(), IntentEnvelope: action.IntentEnvelope, StartGrantEnvelope: action.StartGrantEnvelope, ResultNonce: nonce[:], ResultNonceExpiresAt: timestamppb.New(expires)}, nil
}

func dispatchClock(ctx context.Context, q *devicedb.Queries) (time.Time, error) {
	stamp, err := q.ServiceDispatchClock(ctx)
	if err != nil {
		return time.Time{}, err
	}
	now, ok := finiteTime(stamp)
	if !ok {
		return time.Time{}, errInternalState
	}
	return now, nil
}

func dispatchAudit(ctx context.Context, q *devicedb.Queries, actor *uuid.UUID, action string, id uuid.UUID, reason string) error {
	return q.InsertAuditEvent(ctx, devicedb.InsertAuditEventParams{ID: uuid.New(), ActorID: actor, Action: action, ResourceID: id.String(), Reason: reason})
}

func assignmentAuthorizationDenied(err error) bool {
	return errors.Is(err, identity.ErrAuthorizationDenied) || errors.Is(err, identity.ErrAuthorizationChanged) || errors.Is(err, identity.ErrSubjectUnqualified)
}

func serviceActionRevision(action devicedb.ServiceAction) (uint64, error) {
	n := action.ActionRevision
	if !n.Valid || n.NaN || n.Int == nil || n.Exp != 0 || !n.Int.IsUint64() {
		return 0, errInternalState
	}
	return n.Int.Uint64(), nil
}
