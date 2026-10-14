// SPDX-License-Identifier: Apache-2.0

package dispatch

import (
	"bytes"
	"context"
	"errors"
	"time"

	"lindm/internal/auditkind"
	"lindm/internal/device/secrets"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/rpcreason"
	"lindm/internal/targeting"
)

var resourceReasons = signedReasons{
	invalidStart: "invalid_service_start_request", invalidResult: "invalid_service_result_request", resultAudit: auditkind.ResourceActionResult,
	binding:          reason{connect.CodePermissionDenied, "resource_action_binding_rejected"},
	challenge:        reason{connect.CodePermissionDenied, "resource_challenge_rejected"},
	challengeBinding: reason{connect.CodePermissionDenied, "resource_challenge_binding_rejected"},
	startConflict:    reason{connect.CodeAlreadyExists, "resource_start_conflict"},
	startWindow:      reason{connect.CodeFailedPrecondition, "resource_start_window_empty"},
	nonce:            reason{connect.CodePermissionDenied, "resource_result_nonce_rejected"},
	attestation:      reason{connect.CodePermissionDenied, "resource_result_rejected"},
	resultConflict:   reason{connect.CodeAlreadyExists, "resource_result_conflict"},
	ungranted:        reason{connect.CodePermissionDenied, "resource_result_binding_rejected"},
}

func (s *Service) AuthorizeResourceStart(ctx context.Context, req *connect.Request[devicev1.AuthorizeResourceStartRequest]) (*connect.Response[devicev1.AuthorizeResourceStartResponse], error) {
	envelope, err := authorizeSignedStart(ctx, s, core.Message(req), new(agentv1.ResourceExecutionChallenge), &resourceStart{})
	if err != nil {
		return nil, err
	}
	return core.NoStore(&devicev1.AuthorizeResourceStartResponse{StartGrantEnvelope: envelope}), nil
}

// resourceStart is the resource-execution half of start authorization. Lost
// actor authority, a changed assignment or paused targeting durably close the
// unstarted action instead of leaving it to expire.
type resourceStart struct {
	captured devicedb.ResourceAction
	intent   *agentv1.ResourceExecutionIntent
	approval *identity.Authorization
	// denied is authority lost after capture; it closes the action.
	denied     error
	head       devicedb.ResourceAssignment
	action     devicedb.ResourceAction
	actionHead uuid.UUID
	fence      targeting.DispatchFence
}

var _ startKind[*agentv1.ResourceExecutionChallenge] = (*resourceStart)(nil)

func (*resourceStart) reasons() signedReasons { return resourceReasons }

func (k *resourceStart) capture(ctx context.Context, s *Service, id uuid.UUID) (signedRow, error) {
	var err error
	k.captured, err = devicedb.New(s.Pool).GetResourceAction(ctx, id)
	return resourceRow(k.captured), err
}

func (k *resourceStart) decode() error {
	k.intent = new(agentv1.ResourceExecutionIntent)
	if err := proto.Unmarshal(k.captured.IntentDocument, k.intent); err != nil {
		return core.MapErr(core.ErrInternalState)
	}
	if k.intent.GetDesired().GetEncryptionCompliance() != nil {
		return rpcreason.Error(connect.CodeFailedPrecondition, "resource_read_only")
	}
	return nil
}

func (k *resourceStart) binds(challenge *agentv1.ResourceExecutionChallenge, digest []byte) bool {
	intent := k.intent
	return challenge.GetDeploymentId() == intent.GetDeploymentId() && challenge.GetDeviceId() == intent.GetDeviceId() && challenge.GetEnrollmentGeneration() == intent.GetEnrollmentGeneration() && challenge.GetActionId() == intent.GetActionId() && challenge.GetDesiredRevision() == intent.GetDesiredRevision() && challenge.GetResourceSequence() == intent.GetResourceSequence() && challenge.GetRecoveryEpoch() == intent.GetRecoveryEpoch() && proto.Equal(challenge.GetRef(), intent.GetDesired().GetRef()) && challenge.GetOperation() == intent.GetOperation() && bytes.Equal(challenge.GetIntentSha256(), digest)
}

func (k *resourceStart) authorize(ctx context.Context, s *Service) error {
	actor, err := uuid.Parse(k.intent.GetActorId())
	if err != nil {
		return core.MapErr(core.ErrInternalState)
	}
	k.approval, k.denied = s.Identity.AuthorizeFresh(ctx, actor, identity.PermissionAssignResources)
	if k.denied != nil && !assignmentAuthorizationDenied(k.denied) {
		return core.ExecutionError(k.denied)
	}
	return nil
}

// lock relocks fresh authority, then targeting, then execution authority.
func (k *resourceStart) lock(ctx context.Context, s *Service, st *startState[*agentv1.ResourceExecutionChallenge]) error {
	if k.approval != nil {
		// A start never modifies the assigning actor; see getResourceWork.
		if err := s.Identity.LockAuthorizationShared(ctx, st.tx, k.approval, identity.PermissionAssignResources); err != nil {
			if !assignmentAuthorizationDenied(err) {
				return core.ExecutionError(err)
			}
			k.denied = err
		}
	}
	// The action's head assignment and its target preview are immutable, so
	// the captured row selects the same fence that admit later relies on.
	planned, err := ResourceActionHead(k.captured, k.intent)
	if err != nil {
		return core.MapErr(err)
	}
	if k.fence, err = s.Targeting.LockDispatch(ctx, st.tx, planned); err != nil {
		return core.MapErr(err)
	}
	if k.approval == nil || k.denied != nil {
		return nil
	}
	if st.snapshot, st.verifier, err = s.Execution.CurrentInTransaction(ctx, st.tx); err != nil {
		return core.ExecutionError(err)
	}
	return nil
}

func (k *resourceStart) lockAction(ctx context.Context, s *Service, st *startState[*agentv1.ResourceExecutionChallenge]) (signedRow, error) {
	if k.approval != nil && k.denied == nil {
		if err := core.RequireDeviceScope(ctx, st.q, k.approval.Principal(), identity.PermissionAssignResources, st.principal.DeviceID); err != nil {
			if !errors.Is(err, core.ErrNotFound) {
				return signedRow{}, core.MapErr(err)
			}
			k.denied = identity.ErrAuthorizationDenied
		}
	}
	// Delivered material was authorized by the actor's secrets.manage authority;
	// losing it is an authority change like any other, never a silent start.
	if k.approval != nil && k.denied == nil && len(k.intent.GetSecrets()) != 0 {
		denied, err := secrets.SecretDeliveryAuthority(ctx, st.q, k.approval, st.principal.DeviceID)
		if err != nil {
			return signedRow{}, core.MapErr(err)
		}
		if denied != "" {
			k.denied = identity.ErrAuthorizationDenied
		}
	}
	head, err := st.q.LockResourceAssignment(ctx, st.principal.GenerationID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return signedRow{}, core.MapErr(err)
	}
	k.head = head
	if k.action, err = st.q.LockResourceAction(ctx, st.id); err != nil {
		return signedRow{}, core.MapErr(err)
	}
	if k.actionHead, err = ResourceActionHead(k.action, k.intent); err != nil {
		return signedRow{}, core.MapErr(err)
	}
	if err := requireReleaseBinding(ctx, st.q, k.action, k.intent); err != nil {
		return signedRow{}, err
	}
	if err := st.q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{ID: st.principal.DeviceID, LastSeenAt: core.Timestamptz(st.now)}); err != nil {
		return signedRow{}, core.MapErr(err)
	}
	return resourceRow(k.action), nil
}

func (k *resourceStart) admit(ctx context.Context, s *Service, st *startState[*agentv1.ResourceExecutionChallenge]) (bool, error) {
	if err := core.RequireActionRestriction(ctx, st.q, st.principal.DeviceID, nil); err != nil {
		return false, core.MapErr(err)
	}
	if k.action.ClosedAt.Valid {
		return false, rpcreason.Error(connect.CodeFailedPrecondition, "resource_action_closed")
	}
	if k.action.ClosedReason != "" {
		return false, rpcreason.Error(connect.CodePermissionDenied, k.action.ClosedReason)
	}
	eligible, err := s.Targeting.CheckExecution(ctx, st.tx, k.fence, st.principal.DeviceID, st.principal.GenerationID, k.actionHead)
	if err != nil {
		return false, core.MapErr(err)
	}
	refusal := ""
	switch {
	case k.head.ID != k.actionHead:
		refusal = "assignment_changed"
	case !eligible:
		refusal = "targeting_paused_or_changed"
	case !st.now.Before(k.action.ExpiresAt.Time):
		refusal = "expired_unstarted"
	case k.denied != nil || k.approval.Version() != k.intent.GetAuthorizationVersion():
		refusal = "authority_changed"
	}
	if refusal == "" {
		return false, nil
	}
	if err := closeUnstartedResourceAction(ctx, st.q, &k.action, refusal, st.now); err != nil {
		return false, core.MapErr(err)
	}
	if refusal == "authority_changed" && k.head.ID == k.actionHead {
		if err := st.q.BlockResourceAssignment(ctx, devicedb.BlockResourceAssignmentParams{ID: k.head.ID, BlockedReason: "assignment_authority_changed"}); err != nil {
			return false, core.MapErr(err)
		}
	}
	return true, rpcreason.Error(connect.CodePermissionDenied, refusal)
}

func (k *resourceStart) verifyIntent(ctx context.Context, st *startState[*agentv1.ResourceExecutionChallenge]) error {
	if _, err := st.verifier.VerifyResourceIntent(ctx, st.snapshot.Root, st.snapshot.Delegation, k.action.IntentEnvelope, st.now); err != nil {
		return rpcreason.Error(connect.CodePermissionDenied, "resource_start_authority_rejected")
	}
	return nil
}

func (k *resourceStart) limits(st *startState[*agentv1.ResourceExecutionChallenge], issued time.Time) []time.Time {
	return []time.Time{issued.Add(k.approval.ExpiresAt().Sub(st.now)), k.intent.GetExpiresAt().AsTime()}
}

func (k *resourceStart) grant(st *startState[*agentv1.ResourceExecutionChallenge], expires time.Time) proto.Message {
	return &agentv1.ResourceExecutionStartGrant{Challenge: st.challenge, ActorId: k.intent.GetActorId(), AuthorizationVersion: k.approval.Version(), RootVersion: st.snapshot.Root.GetVersion(), DelegationVersion: st.snapshot.Delegation.GetVersion(), NotBefore: st.challenge.GetIssuedAt(), ExpiresAt: timestamppb.New(expires)}
}

func (*resourceStart) signFailed(error) error {
	return rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_rejected")
}

func (k *resourceStart) verifyGrant(ctx context.Context, st *startState[*agentv1.ResourceExecutionChallenge], envelope []byte) error {
	if _, err := st.verifier.VerifyResourceStart(ctx, st.snapshot.Root, st.snapshot.Delegation, envelope, k.intent, st.challenge, st.challenge.GetIssuedAt().AsTime()); err != nil {
		return rpcreason.Error(connect.CodePermissionDenied, "resource_start_authority_rejected")
	}
	return nil
}

func (k *resourceStart) persist(ctx context.Context, s *Service, st *startState[*agentv1.ResourceExecutionChallenge], envelope []byte) error {
	if err := st.q.SetResourceGrant(ctx, devicedb.SetResourceGrantParams{ID: st.id, ChallengeProof: st.proof, StartGrantEnvelope: envelope, StartAuthorizedAt: core.Timestamptz(st.now)}); err != nil {
		return core.MapErr(err)
	}
	if err := s.Identity.LockAuthorizationShared(ctx, st.tx, k.approval, identity.PermissionAssignResources); err != nil {
		return core.ExecutionError(err)
	}
	// The audit append holds the deployment-wide chain head until commit, so it
	// is the transaction's last statement.
	if err := core.DeviceAudit(ctx, st.q, &k.head.ActorID, auditkind.ResourceActionStart, st.id.String(), st.principal.DeviceID, "", "authority", "fresh_actor_authorization"); err != nil {
		return core.MapErr(err)
	}
	return nil
}

func resourceRow(action devicedb.ResourceAction) signedRow {
	return signedRow{id: action.ID, deviceID: action.DeviceID, generationID: action.GenerationID, intentEnvelope: action.IntentEnvelope, challengeProof: action.ChallengeProof, startGrant: action.StartGrantEnvelope, resultNonce: action.ResultNonce, nonceExpiresAt: action.NonceExpiresAt, revision: action.ActionRevision, attestation: action.AttestationEnvelope, attestationCertificate: action.AttestationCertificate, closed: action.ClosedAt.Valid}
}

// requireReleaseBinding refuses an action whose release no longer describes it.
func requireReleaseBinding(ctx context.Context, q *devicedb.Queries, action devicedb.ResourceAction, intent *agentv1.ResourceExecutionIntent) error {
	if action.ReleaseID == nil {
		return nil
	}
	release, err := q.GetResourceRelease(ctx, *action.ReleaseID)
	if err != nil {
		return core.MapErr(err)
	}
	if err := validateReleaseAction(release, action, intent); err != nil {
		return rpcreason.Error(connect.CodePermissionDenied, "resource_release_binding_rejected")
	}
	return nil
}
