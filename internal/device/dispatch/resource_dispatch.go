package dispatch

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"lindm/internal/auditkind"
	"lindm/internal/device/secrets"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/executionauthority"
	"lindm/internal/identity"
	"lindm/internal/resource"
	"lindm/internal/rpcreason"
	"lindm/internal/targeting"
	"lindm/internal/trust"
)

func (s *Service) GetResourceWork(ctx context.Context, req *connect.Request[devicev1.GetResourceWorkRequest]) (*connect.Response[devicev1.GetResourceWorkResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	principal, ok := core.DevicePrincipalFromContext(ctx)
	if !ok {
		return nil, rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_service_work_request")
	}
	idle, err := s.resourceWorkIdle(ctx, principal, req.Msg.GetSessionEpoch())
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	if idle {
		return core.NoStore(&devicev1.GetResourceWorkResponse{}), nil
	}
	work, choice, err := s.getResourceWork(ctx, principal, req.Msg.GetSessionEpoch(), nil, nil, nil)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	if choice != nil {
		if s.Identity == nil {
			return nil, rpcreason.Error(connect.CodeFailedPrecondition, "resource_authorization_unavailable")
		}
		approval, authorizationErr := s.Identity.AuthorizeFresh(ctx, choice.ActorID, identity.PermissionAssignResources)
		if authorizationErr != nil && !assignmentAuthorizationDenied(authorizationErr) {
			return nil, core.ExecutionError(authorizationErr)
		}
		work, _, err = s.getResourceWork(ctx, principal, req.Msg.GetSessionEpoch(), choice, approval, authorizationErr)
		if err != nil {
			return nil, core.ExecutionError(err)
		}
	}
	return core.NoStore(&devicev1.GetResourceWorkResponse{Work: work}), nil
}

// An empty poll linearizes at its read snapshot. A concurrently assigned head is
// observed by the next poll; nothing is leased, signed or acknowledged here.
// Any head/open action falls back to the complete locked path below, which
// rechecks device authority and the assigning actor before minting work.
func (s *Service) resourceWorkIdle(ctx context.Context, principal core.DevicePrincipal, epoch uint64) (bool, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	pending, err := q.HasResourceWork(ctx, devicedb.HasResourceWorkParams{GenerationID: principal.GenerationID, DeviceID: principal.DeviceID})
	if err != nil {
		return false, err
	}
	if pending {
		return false, tx.Commit(ctx)
	}
	device, err := s.ReadAuthority(ctx, q, principal)
	if err != nil {
		return false, err
	}
	if uint64(device.Generation.SessionEpoch) != epoch {
		return false, core.ErrSessionFenced
	}
	if err := s.RequireReleaseCompatibility(ctx, q, principal.GenerationID, epoch); err != nil {
		return false, err
	}
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return false, err
	}
	if !core.EnrollmentIssuanceResumable(device.Certificate, now) {
		return false, core.ErrCertificateRejected
	}
	restriction, err := q.GetDeviceActionRestriction(ctx, principal.DeviceID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	if restriction.Quarantined {
		// Keep both quarantine denial and durable expiry on the existing write
		// path. A read-only poll must not invent a second quarantine policy.
		return false, tx.Commit(ctx)
	}
	return true, tx.Commit(ctx)
}

// The first transaction either replays work or captures the exact mint choice.
// Only after it ends is the directory consulted. The second transaction fences
// that approval before authority/device/head/action locks and rechecks the choice.
func (s *Service) getResourceWork(ctx context.Context, principal core.DevicePrincipal, epoch uint64, choice *devicedb.ResourceAssignment, approval *identity.Authorization, authorizationErr error) (*devicev1.ResourceWork, *devicedb.ResourceAssignment, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if approval != nil {
		// Minting never modifies the assigning actor: a rollout's concurrent
		// dispatches share its authority fence instead of serializing on it.
		if err := s.Identity.LockAuthorizationShared(ctx, tx, approval, identity.PermissionAssignResources); err != nil {
			if !assignmentAuthorizationDenied(err) {
				return nil, nil, err
			}
			authorizationErr = err
		}
	}
	fence, err := s.lockGenerationDispatch(ctx, tx, principal.GenerationID)
	if err != nil {
		return nil, nil, err
	}
	var snapshot *executionauthority.Snapshot
	var verifier *trust.ExecutionVerifier
	if choice != nil && authorizationErr == nil {
		if s.Signing == nil {
			return nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
		}
		snapshot, verifier, err = s.Execution.CurrentInTransaction(ctx, tx)
		if err != nil {
			return nil, nil, err
		}
	}
	q := devicedb.New(tx)
	device, err := s.LockAuthority(ctx, q, principal)
	if err != nil {
		return nil, nil, err
	}
	if uint64(device.Generation.SessionEpoch) != epoch {
		return nil, nil, core.ErrSessionFenced
	}
	if approval != nil {
		if err := core.RequireDeviceScope(ctx, q, approval.Principal(), identity.PermissionAssignResources, principal.DeviceID); err != nil {
			if !errors.Is(err, core.ErrNotFound) {
				return nil, nil, err
			}
			authorizationErr = identity.ErrAuthorizationDenied
		}
	}
	head, headErr := q.LockResourceAssignment(ctx, principal.GenerationID)
	if headErr != nil && !errors.Is(headErr, pgx.ErrNoRows) {
		return nil, nil, headErr
	}
	action, actionErr := q.GetOpenResourceAction(ctx, principal.DeviceID)
	if actionErr != nil && !errors.Is(actionErr, pgx.ErrNoRows) {
		return nil, nil, actionErr
	}
	if actionErr != nil || len(action.StartGrantEnvelope) == 0 {
		if err := s.RequireReleaseCompatibility(ctx, q, principal.GenerationID, epoch); err != nil {
			return nil, nil, err
		}
	}
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	if !core.EnrollmentIssuanceResumable(device.Certificate, now) {
		return nil, nil, core.ErrCertificateRejected
	}
	if err := q.TouchDeviceLastSeen(ctx, devicedb.TouchDeviceLastSeenParams{ID: principal.DeviceID, LastSeenAt: core.Timestamptz(now)}); err != nil {
		return nil, nil, err
	}
	if actionErr == nil && len(action.StartGrantEnvelope) == 0 {
		intent := new(agentv1.ResourceExecutionIntent)
		if err := proto.Unmarshal(action.IntentDocument, intent); err != nil {
			return nil, nil, core.ErrInternalState
		}
		actionHead, err := ResourceActionHead(action, intent)
		if err != nil {
			return nil, nil, err
		}
		reason := action.ClosedReason
		if reason == "" {
			switch {
			case actionHead != head.ID:
				reason = "assignment_changed"
			case !now.Before(action.ExpiresAt.Time):
				reason = "expired_unstarted"
			case intent.GetPreparation() != nil:
				eligible, err := s.Targeting.CheckExecution(ctx, tx, fence, principal.DeviceID, principal.GenerationID, head.ID)
				if err != nil {
					return nil, nil, dispatchFenceError(err)
				}
				if !eligible {
					reason = "targeting_paused_or_changed"
				} else if head.BlockedReason != "" {
					reason = "authority_changed"
				}
			}
		}
		if reason != "" {
			if err := closeUnstartedResourceAction(ctx, q, &action, reason, now); err != nil {
				return nil, nil, err
			}
			if action.ClosedAt.Valid {
				actionErr = pgx.ErrNoRows
			}
		}
	}
	if actionErr == nil {
		// Issued start authority may have caused an effect. Expiry, reassignment and
		// actor revocation never manufacture a replacement for an unreported effect.
		if action.GenerationID != principal.GenerationID {
			return nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "resource_action_generation_pending")
		}
		work, err := IssueResourceNonce(ctx, q, action, now)
		if err != nil {
			return nil, nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, nil, err
		}
		return work, nil, nil
	}
	return s.selectResourceWork(ctx, tx, q, fence, principal, choice, approval, authorizationErr, snapshot, verifier, head, headErr, now)
}

func (s *Service) selectResourceWork(ctx context.Context, tx pgx.Tx, q *devicedb.Queries, fence targeting.DispatchFence, principal core.DevicePrincipal, choice *devicedb.ResourceAssignment, approval *identity.Authorization, authorizationErr error, snapshot *executionauthority.Snapshot, verifier *trust.ExecutionVerifier, head devicedb.ResourceAssignment, headErr error, now time.Time) (*devicev1.ResourceWork, *devicedb.ResourceAssignment, error) {
	if err := core.RequireActionRestriction(ctx, q, principal.DeviceID, nil); err != nil {
		return nil, nil, err
	}
	if errors.Is(headErr, pgx.ErrNoRows) || head.BlockedReason != "" {
		return nil, nil, tx.Commit(ctx)
	}
	resources, err := q.ListAssignmentResources(ctx, head.ID)
	if err != nil {
		return nil, nil, err
	}
	// The head is locked: decide platform-limited rows against the device's
	// latest facts before any candidate, even while targeting withholds work.
	if err := refreshApplicability(ctx, q, head, resources); err != nil {
		return nil, nil, err
	}
	eligible, err := s.Targeting.CheckExecution(ctx, tx, fence, principal.DeviceID, principal.GenerationID, head.ID)
	if err != nil {
		return nil, nil, dispatchFenceError(err)
	}
	if !eligible {
		return nil, nil, tx.Commit(ctx)
	}
	release, candidate, source, err := pendingResourceRelease(ctx, q, head, resources)
	if err != nil {
		return nil, nil, err
	}
	if release == nil {
		source = head
		candidate, err = EligibleResource(resources, now, time.Duration(head.ReconcileIntervalSeconds)*time.Second)
		if err != nil {
			return nil, nil, err
		}
	}
	if candidate == nil {
		return nil, nil, tx.Commit(ctx)
	}
	if choice == nil {
		if s.Signing == nil {
			return nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_unconfigured")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, nil, err
		}
		return nil, &head, nil
	}
	if choice.ID != head.ID {
		return nil, nil, rpcreason.Error(connect.CodeAborted, "resource_assignment_conflict")
	}
	if authorizationErr != nil || approval.Version() != uint64(head.AuthorizationVersion) {
		if err := q.BlockResourceAssignment(ctx, devicedb.BlockResourceAssignmentParams{ID: head.ID, BlockedReason: "assignment_authority_changed"}); err != nil {
			return nil, nil, err
		}
		return nil, nil, tx.Commit(ctx)
	}
	if snapshot == nil || snapshot.Delegation == nil {
		return nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_authority_unconfigured")
	}
	return s.mintResourceWork(ctx, tx, q, principal, approval, snapshot, verifier, head, source, resources, candidate, release, now)
}

// dispatchFenceError makes a head that became rollout-bound after the shared
// fence was chosen the existing retryable assignment conflict.
func dispatchFenceError(err error) error {
	if errors.Is(err, targeting.ErrDispatchFence) {
		return rpcreason.Error(connect.CodeAborted, "resource_assignment_conflict")
	}
	return err
}

// lockGenerationDispatch takes the targeting dispatch fence for the
// generation's current head. The unlocked head read only selects the fence
// mode; the locked head is checked against it before any rollout state is read.
func (s *Service) lockGenerationDispatch(ctx context.Context, tx pgx.Tx, generation uuid.UUID) (targeting.DispatchFence, error) {
	planned := uuid.Nil
	if current, err := devicedb.New(tx).GetResourceAssignment(ctx, generation); err == nil {
		planned = current.ID
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return targeting.DispatchFence{}, err
	}
	return s.Targeting.LockDispatch(ctx, tx, planned)
}

func (s *Service) mintResourceWork(ctx context.Context, tx pgx.Tx, q *devicedb.Queries, principal core.DevicePrincipal, approval *identity.Authorization, snapshot *executionauthority.Snapshot, verifier *trust.ExecutionVerifier, head, source devicedb.ResourceAssignment, resources []devicedb.ResourceAssignmentResource, candidate *policyv1.ProfileResource, release *devicedb.ResourceRelease, now time.Time) (*devicev1.ResourceWork, *devicedb.ResourceAssignment, error) {
	operation := resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE
	if release != nil {
		operation = resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE
	}
	// Secrets resolve before the sequence advances: a blocked or waiting head
	// consumes no sequence and never mints work that lacks its sealed material.
	id := uuid.New()
	deliveries, reason, err := s.secrets.SealResourceSecrets(ctx, q, approval, principal, id, candidate.GetDesired(), operation)
	if err != nil {
		return nil, nil, err
	}
	if reason == secrets.SecretWaitDeviceKey {
		if err := secrets.WaitResource(ctx, q, head.ID, resources, candidate, reason); err != nil {
			return nil, nil, err
		}
		return nil, nil, tx.Commit(ctx)
	}
	if reason != "" {
		if err := q.BlockResourceAssignment(ctx, devicedb.BlockResourceAssignmentParams{ID: head.ID, BlockedReason: reason}); err != nil {
			return nil, nil, err
		}
		return nil, nil, tx.Commit(ctx)
	}
	capacity, err := q.ResourceDispatchCapacity(ctx, principal.GenerationID)
	if err != nil {
		return nil, nil, err
	}
	if capacity.Actions >= 262144 {
		return nil, nil, rpcreason.Error(connect.CodeResourceExhausted, "resource_action_capacity")
	}
	sequence, err := q.NextResourceSequence(ctx, devicedb.NextResourceSequenceParams{GenerationID: principal.GenerationID, ResourceKind: int16(candidate.GetDesired().GetRef().GetKind()), CanonicalKey: candidate.GetDesired().GetRef().GetCanonicalKey()})
	if err != nil {
		return nil, nil, err
	}
	notBefore := now.Add(-trust.MaxDeviceClockSkew)
	if snapshot.Delegation.GetNotBefore().AsTime().After(notBefore) {
		notBefore = snapshot.Delegation.GetNotBefore().AsTime()
	}
	expires := notBefore.Add(12 * time.Minute)
	if snapshot.Delegation.GetExpiresAt().AsTime().Before(expires) {
		expires = snapshot.Delegation.GetExpiresAt().AsTime()
	}
	if !expires.After(notBefore) || !expires.After(now) {
		return nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_window_empty")
	}
	ownership, err := s.resourceOwnership(ctx, tx, source, candidate)
	if err != nil {
		return nil, nil, err
	}
	ownership.AssignmentId = head.ID.String()
	intent := &agentv1.ResourceExecutionIntent{DeploymentId: s.DeploymentID.String(), DeviceId: principal.DeviceID.String(), EnrollmentGeneration: principal.GenerationID.String(), ActionId: id.String(), DesiredRevision: head.ID.String(), ActorId: head.ActorID.String(), ResourceSequence: uint64(sequence), RecoveryEpoch: snapshot.Delegation.GetMinimumRecoveryEpoch(), RootVersion: snapshot.Root.GetVersion(), DelegationVersion: snapshot.Delegation.GetVersion(), AuthorizationVersion: approval.Version(), NotBefore: timestamppb.New(notBefore), ExpiresAt: timestamppb.New(expires), Desired: candidate.GetDesired(), Operation: operation, Ownership: ownership}
	for _, delivery := range deliveries {
		intent.Secrets = append(intent.Secrets, delivery.Manifest)
	}
	if intent.GetDesired().GetNativePackage() != nil {
		intent.Preparation = &agentv1.ResourceExecutionPreparation{
			Deadline: proto.CloneOf(intent.GetExpiresAt()), MaxCacheBytes: 512 << 20,
		}
	}
	envelope, err := s.Authority.Sign(ctx, intent, s.Signing.PlanKey)
	if err != nil {
		return nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_rejected")
	}
	if _, err := verifier.VerifyResourceIntent(ctx, snapshot.Root, snapshot.Delegation, envelope, now); err != nil {
		return nil, nil, rpcreason.Error(connect.CodeFailedPrecondition, "execution_signing_rejected")
	}
	document, err := proto.Marshal(intent)
	if err != nil {
		return nil, nil, err
	}
	resourceID, _ := uuid.Parse(candidate.GetResourceId())
	if err := q.InsertResourceAction(ctx, devicedb.InsertResourceActionParams{ID: id, DeviceID: principal.DeviceID, GenerationID: principal.GenerationID, AssignmentID: source.ID, ResourceID: resourceID, ResourceSequence: sequence, IntentEnvelope: envelope, IntentDocument: document, IssuedAt: core.Timestamptz(now), ExpiresAt: core.Timestamptz(expires)}); err != nil {
		return nil, nil, err
	}
	if release != nil {
		if err := q.BindResourceReleaseAction(ctx, devicedb.BindResourceReleaseActionParams{ID: id, ReleaseID: &release.ID}); err != nil {
			return nil, nil, err
		}
	} else if err := q.SetAssignmentResourceDisposition(ctx, devicedb.SetAssignmentResourceDispositionParams{AssignmentID: head.ID, ResourceID: resourceID, Disposition: 2}); err != nil {
		return nil, nil, err
	}
	if err := secrets.StoreResourceSecrets(ctx, q, &head.ActorID, id, deliveries); err != nil {
		return nil, nil, err
	}
	action, err := q.LockResourceAction(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	work, err := IssueResourceNonce(ctx, q, action, now)
	if err != nil {
		return nil, nil, err
	}
	if err := s.Identity.LockAuthorizationShared(ctx, tx, approval, identity.PermissionAssignResources); err != nil {
		return nil, nil, err
	}
	// The audit append holds the deployment-wide chain head until commit, so it
	// is the transaction's last statement.
	if err := core.DispatchSystemAudit(ctx, q, &head.ActorID, auditkind.ResourceActionMint, id, "source", "resource_assignment"); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return work, nil, nil
}

// resourceReasonNativeBusy is the server reason for a device-attested, effect-free
// refusal because another native package frontend held the package lock.
const ResourceReasonNativeBusy = "native_package_manager_busy"

// ResourceReasonUnsafeToolPath is the server reason for a device-attested,
// effect-free refusal because a native tool's ancestry is not root-protected;
// the device's inventory tool custody names the path and its mode.
const ResourceReasonUnsafeToolPath = "native_tool_path_unprotected"

func EligibleResource(rows []devicedb.ResourceAssignmentResource, now time.Time, interval time.Duration) (*policyv1.ProfileResource, error) {
	dispositions := make(map[string]int16, len(rows))
	desired := make(map[string]*policyv1.ProfileResource, len(rows))
	for _, row := range rows {
		item := new(policyv1.ProfileResource)
		if err := proto.Unmarshal(row.Document, item); err != nil {
			return nil, core.ErrInternalState
		}
		desired[resourceRefKey(item.GetDesired().GetRef())] = item
		disposition := row.Disposition
		// Due dependencies must be reverified before their dependents. The rows
		// are already topologically ordered, so checks retain the initial order.
		recheck := interval
		if row.VerificationMaxAgeSeconds > 0 {
			recheck = min(recheck, time.Duration(row.VerificationMaxAgeSeconds)*time.Second/2)
		}
		if disposition == 3 && (!row.LastVerifiedAt.Valid || !now.Before(row.LastVerifiedAt.Time.Add(recheck))) {
			disposition = 1
		}
		// A native-busy hold (another package frontend, such as a release
		// upgrade, owned the database) is retried one reconcile interval after
		// the server recorded it; every other block waits for a new assignment.
		if disposition == 5 && row.Reason == ResourceReasonNativeBusy && row.ObservedAt.Valid && !now.Before(row.ObservedAt.Time.Add(interval)) {
			disposition = 1
		}
		dispositions[resourceRefKey(item.GetDesired().GetRef())] = disposition
	}
	for _, row := range rows {
		resource := desired[resourceRefKeyFromRow(row)]
		if resource == nil {
			return nil, core.ErrInternalState
		}
		if dispositions[resourceRefKey(resource.GetDesired().GetRef())] != 1 {
			continue
		}
		eligible := true
		for _, dependency := range resource.GetDependsOn() {
			key := resourceRefKey(dependency.GetRef())
			if dispositions[key] != 3 || !ResourceDependencySatisfied(desired[key], dependency.GetCondition()) {
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

// Asynchronous preflight has owned durable work even before a grant. Retain its
// action fence until the executor acknowledges cleanup; immediate providers keep
// their existing unstarted closure behavior.
func closeUnstartedResourceAction(ctx context.Context, q *devicedb.Queries, action *devicedb.ResourceAction, reason string, now time.Time) error {
	if len(action.StartGrantEnvelope) != 0 {
		return core.ErrInternalState
	}
	intent := new(agentv1.ResourceExecutionIntent)
	if err := proto.Unmarshal(action.IntentDocument, intent); err != nil {
		return core.ErrInternalState
	}
	disposition := int16(1)
	if intent.GetPreparation() != nil {
		if action.ClosedReason == "" {
			if err := q.RequestResourcePreparationCancellation(ctx, devicedb.RequestResourcePreparationCancellationParams{ID: action.ID, ClosedReason: reason}); err != nil {
				return err
			}
			action.ClosedReason = reason
		}
		reason, disposition = action.ClosedReason, 2
	} else {
		if err := q.CloseResourceAction(ctx, devicedb.CloseResourceActionParams{ID: action.ID, ClosedAt: core.Timestamptz(now), ClosedReason: reason}); err != nil {
			return err
		}
		action.ClosedAt, action.ClosedReason = core.Timestamptz(now), reason
	}
	if action.ReleaseID != nil {
		return nil
	}
	return q.SetAssignmentResourceDisposition(ctx, devicedb.SetAssignmentResourceDispositionParams{AssignmentID: action.AssignmentID, ResourceID: action.ResourceID, Disposition: disposition, Reason: reason})
}

func IssueResourceNonce(ctx context.Context, q *devicedb.Queries, action devicedb.ResourceAction, now time.Time) (*devicev1.ResourceWork, error) {
	// Replays carry the exact stored ciphertext; the signed manifest binds it.
	sealed, err := secrets.ResourceActionSecrets(ctx, q, action)
	if err != nil {
		return nil, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	expires := now.Add(time.Minute)
	if err := q.SetResourceNonce(ctx, devicedb.SetResourceNonceParams{ID: action.ID, ResultNonce: nonce[:], NonceExpiresAt: core.Timestamptz(expires)}); err != nil {
		return nil, err
	}
	return &devicev1.ResourceWork{ActionId: action.ID.String(), IntentEnvelope: action.IntentEnvelope, StartGrantEnvelope: action.StartGrantEnvelope, ResultNonce: nonce[:], ResultNonceExpiresAt: timestamppb.New(expires), CancelPreparation: !action.ClosedAt.Valid && action.ClosedReason != "", SealedSecrets: sealed}, nil
}

func assignmentAuthorizationDenied(err error) bool {
	return errors.Is(err, identity.ErrAuthorizationDenied) || errors.Is(err, identity.ErrAuthorizationChanged) || errors.Is(err, identity.ErrSubjectUnqualified)
}

func resourceActionRevision(action devicedb.ResourceAction) (uint64, error) {
	return signedRevision(action.ActionRevision)
}

// signedRevision decodes a stored executor action revision; anything but a
// finite unsigned integer is damaged state.
func signedRevision(n pgtype.Numeric) (uint64, error) {
	if !n.Valid || n.NaN || n.Int == nil || n.Exp != 0 || !n.Int.IsUint64() {
		return 0, core.ErrInternalState
	}
	return n.Int.Uint64(), nil
}

func (s *Service) resourceOwnership(ctx context.Context, tx pgx.Tx, head devicedb.ResourceAssignment, candidate *policyv1.ProfileResource) (*agentv1.ResourceOwnershipBinding, error) {
	if err := resource.ValidateDesired(candidate.GetDesired()); err != nil {
		return nil, err
	}
	binding := &agentv1.ResourceOwnershipBinding{AssignmentId: head.ID.String(), ResourceId: candidate.GetResourceId(), Policy: proto.CloneOf(candidate.GetOwnership())}
	if binding.GetPolicy().GetMode() == resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION {
		if head.AdoptionApprovalID == nil {
			return nil, identity.ErrApprovalRequired
		}
		approval := head.AdoptionApprovalID.String()
		binding.Policy.AdoptionApprovalId = &approval
	}
	if head.RevisionID != nil {
		assignment := new(adminv1.ResourceAssignment)
		if err := proto.Unmarshal(head.Document, assignment); err != nil {
			return nil, err
		}
		if assignment.GetRevisionId() != head.RevisionID.String() {
			return nil, core.ErrInternalState
		}
		binding.Sources = []*agentv1.ResourceOwnershipSource{{ProfileId: assignment.GetProfileId(), ProfileRevision: assignment.GetRevisionId(), ResourceId: candidate.GetResourceId()}}
		return binding, nil
	}
	preview, err := s.Targeting.ExecutionPreview(ctx, tx, head.DeviceID, head.GenerationID, head.ID)
	if err != nil {
		return nil, err
	}
	var resolved *policyv1.ResolvedResource
	for _, item := range preview.GetResolution().GetResources() {
		if proto.Equal(item.GetRef(), candidate.GetDesired().GetRef()) {
			if resolved != nil || !proto.Equal(item.GetResource(), candidate) {
				return nil, core.ErrInternalState
			}
			resolved = item
		}
	}
	if resolved == nil || len(resolved.GetContributingRevisionIds()) == 0 {
		return nil, core.ErrInternalState
	}
	for _, id := range resolved.GetContributingRevisionIds() {
		revisionID, err := uuid.Parse(id)
		if err != nil {
			return nil, core.ErrInternalState
		}
		revision, err := s.Profiles.GetRevisionInTransaction(ctx, tx, revisionID)
		if err != nil {
			return nil, err
		}
		var source *policyv1.ProfileResource
		for _, item := range revision.GetSpec().GetResources() {
			if proto.Equal(item.GetDesired().GetRef(), candidate.GetDesired().GetRef()) {
				if source != nil {
					return nil, core.ErrInternalState
				}
				source = item
			}
		}
		if source == nil {
			return nil, core.ErrInternalState
		}
		binding.Sources = append(binding.Sources, &agentv1.ResourceOwnershipSource{ProfileId: revision.GetProfileId(), ProfileRevision: revision.GetRevisionId(), ResourceId: source.GetResourceId()})
	}
	return binding, nil
}
