package dispatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sort"
	"time"

	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
	"lindm/internal/policy"
	"lindm/internal/rpcreason"
)

func (s *Service) SetResourceAssignment(ctx context.Context, req *connect.Request[adminv1.SetResourceAssignmentRequest]) (*connect.Response[adminv1.SetResourceAssignmentResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionAssignResources)
	if err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil || core.HasNUL(req.Msg.GetReason()) {
		return nil, core.Invalid("invalid_service_assignment")
	}
	if s.Identity == nil {
		return nil, rpcreason.Error(connect.CodeFailedPrecondition, "resource_authorization_unavailable")
	}
	approval, err := s.Identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionAssignResources)
	if err != nil {
		return nil, core.ExecutionError(err)
	}
	consumption, err := s.PrepareActionApproval(ctx, actor, identity.PermissionAssignResources, req.Msg.GetApprovalId(), req.Msg)
	if err != nil {
		return nil, err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.LockActionApproval(ctx, tx, consumption, approval, identity.PermissionAssignResources); err != nil {
		return nil, core.ApprovalError(err)
	}
	q := devicedb.New(tx)
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	device, err := core.LockDeviceScope(ctx, q, approval.Principal(), identity.PermissionAssignResources, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, core.MapErr(err)
	}
	canonical := proto.CloneOf(req.Msg)
	canonical.ApprovalId = ""
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(canonical)
	if err != nil {
		return nil, core.MapErr(err)
	}
	digest := sha256.Sum256(encoded)
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	previous, err := q.GetResourceAssignmentRequest(ctx, requestID)
	if err == nil {
		if previous.ActorID != actor.ID || !bytes.Equal(previous.RequestDigest, digest[:]) {
			return nil, core.MapErr(core.ErrIdempotencyConflict)
		}
		result := new(adminv1.ResourceAssignment)
		if err := proto.Unmarshal(previous.Document, result); err != nil {
			return nil, core.MapErr(core.ErrInternalState)
		}
		if err := s.LockActionApproval(ctx, tx, consumption, approval, identity.PermissionAssignResources); err != nil {
			return nil, core.ApprovalError(err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, core.MapErr(err)
		}
		return core.NoStore(&adminv1.SetResourceAssignmentResponse{Assignment: result}), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, core.MapErr(err)
	}
	if device.CurrentGenerationID == nil || (device.State != core.StateActive && device.State != core.StatePending) {
		return nil, core.MapErr(core.ErrDeviceRevoked)
	}
	generationID := *device.CurrentGenerationID
	head, err := q.LockResourceAssignment(ctx, generationID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, core.MapErr(err)
	}
	if (err == nil && head.ID.String() != req.Msg.GetExpectedAssignmentId()) || (errors.Is(err, pgx.ErrNoRows) && req.Msg.ExpectedAssignmentId != nil) {
		return nil, rpcreason.Error(connect.CodeAborted, "resource_assignment_conflict")
	}
	capacity, err := q.ResourceDispatchCapacity(ctx, generationID)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if capacity.Assignments >= 65536 {
		return nil, rpcreason.Error(connect.CodeResourceExhausted, "resource_assignment_capacity")
	}
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return nil, core.MapErr(err)
	}
	id := uuid.New()
	assignment := &adminv1.ResourceAssignment{AssignmentId: id.String(), DeviceId: deviceID.String(), EnrollmentGeneration: generationID.String(), ActorId: actor.ID.String(), AssignedAt: timestamppb.New(now), Reason: req.Msg.GetReason()}
	assignment.ReconcileIntervalSeconds = 900
	if req.Msg.ReconcileIntervalSeconds != nil {
		assignment.ReconcileIntervalSeconds = req.Msg.GetReconcileIntervalSeconds()
	}
	var revisionID *uuid.UUID
	var resources []*policyv1.ProfileResource
	if target := req.Msg.GetTarget(); target != nil {
		profile, _ := uuid.Parse(target.GetProfileId())
		revision, _ := uuid.Parse(target.GetRevisionId())
		retained, err := s.Profiles.GetInTransaction(ctx, tx, profile, revision)
		if err != nil {
			return nil, core.ProfileError(err)
		}
		resolved, err := policy.Resolve(ctx, []policy.Assignment{{ProfileID: profile.String(), RevisionID: revision.String(), Spec: retained.GetSpec()}})
		if err != nil {
			return nil, core.ProfileError(err)
		}
		for _, item := range resolved {
			if item.State != policy.ResolutionReady {
				return nil, rpcreason.Error(connect.CodeFailedPrecondition, "resource_resolution_conflict")
			}
		}
		assignment.ProfileId, assignment.RevisionId, assignment.RevisionNumber, assignment.ProfileName = retained.GetProfileId(), retained.GetRevisionId(), retained.GetRevisionNumber(), retained.GetSpec().GetName()
		revisionID = &revision
		resources, err = orderedResources(retained.GetSpec().GetResources())
		if err != nil {
			return nil, core.MapErr(err)
		}
	}
	if resourceAdoptionRequired(resources) && consumption == nil {
		return nil, core.ApprovalError(identity.ErrApprovalRequired)
	}
	document, err := proto.Marshal(assignment)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if err := q.InsertResourceAssignment(ctx, devicedb.InsertResourceAssignmentParams{ID: id, DeviceID: deviceID, GenerationID: generationID, RequestID: requestID, RequestDigest: digest[:], ActorID: actor.ID, AuthorizationVersion: int64(approval.Version()), RevisionID: revisionID, Document: document, AssignedAt: core.Timestamptz(now), ReconcileIntervalSeconds: int32(assignment.GetReconcileIntervalSeconds())}); err != nil {
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) && pgerr.Code == "23505" {
			return nil, core.MapErr(core.ErrIdempotencyConflict)
		}
		return nil, core.MapErr(err)
	}
	if err := insertResourceRows(ctx, q, id, resources); err != nil {
		return nil, core.MapErr(err)
	}
	if resourceAdoptionRequired(resources) {
		approvalID, err := uuid.Parse(req.Msg.GetApprovalId())
		if err != nil {
			return nil, core.ApprovalError(identity.ErrApprovalInvalid)
		}
		if err := q.SetResourceAssignmentAdoptionApproval(ctx, devicedb.SetResourceAssignmentAdoptionApprovalParams{ID: id, AdoptionApprovalID: &approvalID}); err != nil {
			return nil, core.MapErr(err)
		}
	}
	if head.ID != uuid.Nil {
		if err := q.RecordResourceReleases(ctx, devicedb.RecordResourceReleasesParams{NewAssignmentID: id, OldAssignmentID: head.ID, RequestedAt: core.Timestamptz(now)}); err != nil {
			return nil, core.MapErr(err)
		}
	}
	if err := q.SetResourceAssignmentHead(ctx, devicedb.SetResourceAssignmentHeadParams{GenerationID: generationID, AssignmentID: id}); err != nil {
		return nil, core.MapErr(err)
	}
	action, err := q.GetOpenResourceAction(ctx, deviceID)
	if err == nil && len(action.StartGrantEnvelope) == 0 {
		if err := closeUnstartedResourceAction(ctx, q, &action, "assignment_changed", now); err != nil {
			return nil, core.MapErr(err)
		}
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, core.MapErr(err)
	}
	auditAction := "resource_assignment.assign"
	if req.Msg.GetClear() {
		auditAction = "resource_assignment.clear"
	}
	if err := core.DispatchAudit(ctx, q, &actor.ID, auditAction, id, req.Msg.GetReason()); err != nil {
		return nil, core.MapErr(err)
	}
	if err := s.LockActionApproval(ctx, tx, consumption, approval, identity.PermissionAssignResources); err != nil {
		return nil, core.ApprovalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(&adminv1.SetResourceAssignmentResponse{Assignment: assignment}), nil
}

func (s *Service) GetDeviceResourceState(ctx context.Context, req *connect.Request[adminv1.GetDeviceResourceStateRequest]) (*connect.Response[adminv1.GetDeviceResourceStateResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	actor, err := s.Require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_service_assignment")
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, core.MapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	id, _ := uuid.Parse(req.Msg.GetDeviceId())
	device, err := core.LockDeviceScope(ctx, q, actor, identity.PermissionReadFleet, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, core.MapErr(err)
	}
	response := new(adminv1.GetDeviceResourceStateResponse)
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if device.CurrentGenerationID != nil {
		head, err := q.LockResourceAssignment(ctx, *device.CurrentGenerationID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, core.MapErr(err)
		}
		if err == nil {
			response.Assignment = new(adminv1.ResourceAssignment)
			if err := proto.Unmarshal(head.Document, response.Assignment); err != nil {
				return nil, core.MapErr(core.ErrInternalState)
			}
			resources, err := q.ListAssignmentResources(ctx, head.ID)
			if err != nil {
				return nil, core.MapErr(err)
			}
			dispositions := make(map[string]adminv1.ResourceDisposition, len(resources))
			for _, row := range resources {
				resource := new(policyv1.ProfileResource)
				if err := proto.Unmarshal(row.Document, resource); err != nil {
					return nil, core.MapErr(core.ErrInternalState)
				}
				state := &adminv1.ResourceState{ResourceId: row.ResourceID.String(), Desired: resource.GetDesired(), DependsOn: resource.GetDependsOn(), Disposition: adminv1.ResourceDisposition(row.Disposition), Reason: row.Reason}
				if state.Disposition == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_PENDING {
					if head.BlockedReason != "" {
						state.Disposition = adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED
						state.Reason = head.BlockedReason
					} else {
						for _, dependency := range row.DependsOn {
							d := dispositions[dependency.String()]
							if d == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_ATTENTION || d == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED || d == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_UNSUPPORTED {
								state.Disposition = adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED
								state.Reason = "dependency_attention"
								break
							}
							if d != adminv1.ResourceDisposition_RESOURCE_DISPOSITION_SUCCEEDED {
								state.Reason = "dependency_pending"
							}
						}
					}
				}
				dispositions[state.ResourceId] = state.Disposition
				latest, err := q.LatestResourceAction(ctx, devicedb.LatestResourceActionParams{AssignmentID: head.ID, ResourceID: row.ResourceID})
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return nil, core.MapErr(err)
				}
				if err == nil {
					state.LatestAction, err = resourceActionSummary(latest)
					if err != nil {
						return nil, core.MapErr(err)
					}
				}
				state.LastVerifiedAt = core.ProtoTime(row.LastVerifiedAt)
				state.ObservedAt = core.ProtoTime(row.ObservedAt)
				state.Compliance = resourceCompliance(row, state, head, now)
				response.Resources = append(response.Resources, state)
			}
		}
		recent, err := q.RecentResourceActions(ctx, *device.CurrentGenerationID)
		if err != nil {
			return nil, core.MapErr(err)
		}
		for _, action := range recent {
			summary, err := resourceActionSummary(action)
			if err != nil {
				return nil, core.MapErr(err)
			}
			intent := new(agentv1.ResourceExecutionIntent)
			if err := proto.Unmarshal(action.IntentDocument, intent); err != nil {
				return nil, core.MapErr(core.ErrInternalState)
			}
			response.RecentActions = append(response.RecentActions, &adminv1.DeviceResourceAction{AssignmentId: action.AssignmentID.String(), ResourceId: action.ResourceID.String(), Ref: intent.GetDesired().GetRef(), Action: summary})
		}
		releases, err := q.ListResourceReleases(ctx, *device.CurrentGenerationID)
		if err != nil {
			return nil, core.MapErr(err)
		}
		for _, release := range releases {
			response.Releases = append(response.Releases, &adminv1.ResourceRelease{
				ReleaseId: release.ID.String(), Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind(release.ResourceKind), CanonicalKey: release.CanonicalKey},
				SourceAssignmentId: release.SourceAssignmentID.String(), SupersedingAssignmentId: release.SupersedingAssignmentID.String(),
				State: release.State, Reason: release.Reason, RequestedAt: core.ProtoTime(release.RequestedAt), CompletedAt: core.ProtoTime(release.CompletedAt),
			})
		}
	}
	encoded, err := protojson.Marshal(response)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if len(encoded) > core.MaxMessageBytes || proto.Size(response) > core.MaxMessageBytes {
		return nil, rpcreason.Error(connect.CodeResourceExhausted, "resource_state_response_capacity")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	return core.NoStore(response), nil
}

// Kahn ordering chooses the lexically first currently eligible unit at each step.
func orderedResources(resources []*policyv1.ProfileResource) ([]*policyv1.ProfileResource, error) {
	pending := append([]*policyv1.ProfileResource(nil), resources...)
	sort.Slice(pending, func(i, j int) bool {
		return resourceRefKey(pending[i].GetDesired().GetRef()) < resourceRefKey(pending[j].GetDesired().GetRef())
	})
	ordered := make([]*policyv1.ProfileResource, 0, len(pending))
	done := make(map[string]bool, len(pending))
	for len(pending) != 0 {
		found := false
		for i, resource := range pending {
			eligible := true
			for _, dependency := range resource.GetDependsOn() {
				if !done[resourceRefKey(dependency.GetRef())] {
					eligible = false
					break
				}
			}
			if !eligible {
				continue
			}
			ordered = append(ordered, resource)
			done[resourceRefKey(resource.GetDesired().GetRef())] = true
			pending = append(pending[:i], pending[i+1:]...)
			found = true
			break
		}
		if !found {
			return nil, core.ErrInternalState
		}
	}
	return ordered, nil
}

func resourceCompliance(row devicedb.ResourceAssignmentResource, state *adminv1.ResourceState, head devicedb.ResourceAssignment, now time.Time) adminv1.ResourceCompliance {
	if head.BlockedReason != "" || state.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_ATTENTION || state.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_BLOCKED || state.GetDisposition() == adminv1.ResourceDisposition_RESOURCE_DISPOSITION_UNSUPPORTED {
		return adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_ATTENTION
	}
	latest := state.GetLatestAction()
	if latest.GetClosedAt() == nil && latest.GetStartAuthorizedAt() != nil {
		return adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_ATTENTION
	}
	if !row.LastVerifiedAt.Valid {
		return adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_UNKNOWN
	}
	maxAge := 2 * time.Duration(head.ReconcileIntervalSeconds) * time.Second
	if row.VerificationMaxAgeSeconds > 0 {
		maxAge = min(maxAge, time.Duration(row.VerificationMaxAgeSeconds)*time.Second)
	}
	if !now.Before(row.LastVerifiedAt.Time.Add(maxAge)) {
		return adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_STALE
	}
	if row.DriftRemediated {
		return adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_DRIFT_REMEDIATED
	}
	return adminv1.ResourceCompliance_RESOURCE_COMPLIANCE_COMPLIANT
}

func resourceActionSummary(action devicedb.ResourceAction) (*adminv1.ResourceActionSummary, error) {
	revision, err := resourceActionRevision(action)
	if err != nil {
		return nil, err
	}
	summary := &adminv1.ResourceActionSummary{ActionId: action.ID.String(), ResourceSequence: uint64(action.ResourceSequence), IssuedAt: core.ProtoTime(action.IssuedAt), ExpiresAt: core.ProtoTime(action.ExpiresAt), StartAuthorizedAt: core.ProtoTime(action.StartAuthorizedAt), ClosedReason: action.ClosedReason, ClosedAt: core.ProtoTime(action.ClosedAt), ActionRevision: revision, AttestedAt: core.ProtoTime(action.AttestedAt), ReceivedAt: core.ProtoTime(action.ReceivedAt)}
	if len(action.StatusDocument) != 0 {
		summary.Status = new(agentv1.ResourceExecutionStatus)
		if err := proto.Unmarshal(action.StatusDocument, summary.Status); err != nil {
			return nil, core.ErrInternalState
		}
	}
	return summary, nil
}

// The immutable profile revision is copied to the normal service dispatcher, not
// a second execution mechanism. No head exists while approval is pending.
func (s *Service) ActivateProvisioningProfile(ctx context.Context, tx pgx.Tx, token devicedb.ProvisioningToken, receipt devicedb.ProvisioningEnrollment, assignment *adminv1.CreateProvisioningTokenRequest) error {
	if len(assignment.GetProfileRevisionIds()) == 0 {
		return nil
	}
	q := devicedb.New(tx)
	revision, _ := uuid.Parse(assignment.GetProfileRevisionIds()[0])
	profile, err := q.ProvisioningProfileIdentity(ctx, revision)
	if err != nil {
		return err
	}
	retained, err := s.Profiles.GetInTransaction(ctx, tx, profile, revision)
	if err != nil {
		return core.ProfileError(err)
	}
	resources, err := orderedResources(retained.GetSpec().GetResources())
	if err != nil {
		return err
	}
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return err
	}
	id := uuid.New()
	document, err := proto.Marshal(&adminv1.ResourceAssignment{AssignmentId: id.String(), DeviceId: receipt.DeviceID.String(), EnrollmentGeneration: receipt.GenerationID.String(), ActorId: token.CreatedBy.String(), AssignedAt: timestamppb.New(now), Reason: token.Reason, ReconcileIntervalSeconds: 900, ProfileId: retained.GetProfileId(), RevisionId: retained.GetRevisionId(), RevisionNumber: retained.GetRevisionNumber(), ProfileName: retained.GetSpec().GetName()})
	if err != nil {
		return err
	}
	if err := q.InsertResourceAssignment(ctx, devicedb.InsertResourceAssignmentParams{ID: id, DeviceID: receipt.DeviceID, GenerationID: receipt.GenerationID, RequestID: receipt.TransactionID, RequestDigest: receipt.CsrSha256, ActorID: token.CreatedBy, AuthorizationVersion: token.AuthorizationVersion, RevisionID: &revision, Document: document, AssignedAt: core.Timestamptz(now), ReconcileIntervalSeconds: 900}); err != nil {
		return err
	}
	if err := insertResourceRows(ctx, q, id, resources); err != nil {
		return err
	}
	// Enrollment approval is not approval of this exact native adoption. Keep
	// enrollment usable, but require an independently approved admin assignment.
	for _, item := range resources {
		if item.GetOwnership().GetMode() != resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION {
			continue
		}
		resourceID, err := uuid.Parse(item.GetResourceId())
		if err != nil {
			return core.ErrInternalState
		}
		if err := q.SetAssignmentResourceDisposition(ctx, devicedb.SetAssignmentResourceDispositionParams{AssignmentID: id, ResourceID: resourceID, Disposition: int16(adminv1.ResourceDisposition_RESOURCE_DISPOSITION_UNSUPPORTED), Reason: "adoption_approval_required"}); err != nil {
			return err
		}
	}
	if err := q.SetResourceAssignmentHead(ctx, devicedb.SetResourceAssignmentHeadParams{GenerationID: receipt.GenerationID, AssignmentID: id}); err != nil {
		return err
	}
	return core.InsertAudit(ctx, q, &token.CreatedBy, "resource_assignment.assign", id.String(), token.Reason)
}
