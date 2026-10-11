package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sort"
	"time"

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
)

func (s *Service) SetResourceAssignment(ctx context.Context, req *connect.Request[adminv1.SetResourceAssignmentRequest]) (*connect.Response[adminv1.SetResourceAssignmentResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionAssignResources)
	if err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil || hasNUL(req.Msg.GetReason()) {
		return nil, invalid("invalid_service_assignment")
	}
	if s.identity == nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "service_authorization_unavailable")
	}
	approval, err := s.identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionAssignResources)
	if err != nil {
		return nil, executionError(err)
	}
	consumption, err := s.prepareActionApproval(ctx, actor, identity.PermissionAssignResources, req.Msg.GetApprovalId(), req.Msg)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.lockActionApproval(ctx, tx, consumption, approval, identity.PermissionAssignResources); err != nil {
		return nil, approvalError(err)
	}
	q := devicedb.New(tx)
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	device, err := lockDeviceScope(ctx, q, approval.Principal(), identity.PermissionAssignResources, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, mapErr(err)
	}
	canonical := proto.CloneOf(req.Msg)
	canonical.ApprovalId = ""
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(canonical)
	if err != nil {
		return nil, mapErr(err)
	}
	digest := sha256.Sum256(encoded)
	requestID, _ := uuid.Parse(req.Msg.GetRequestId())
	previous, err := q.GetServiceAssignmentRequest(ctx, requestID)
	if err == nil {
		if previous.ActorID != actor.ID || !bytes.Equal(previous.RequestDigest, digest[:]) {
			return nil, mapErr(errIdempotencyConflict)
		}
		result := new(adminv1.ResourceAssignment)
		if err := proto.Unmarshal(previous.Document, result); err != nil {
			return nil, mapErr(errInternalState)
		}
		if err := s.lockActionApproval(ctx, tx, consumption, approval, identity.PermissionAssignResources); err != nil {
			return nil, approvalError(err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return noStore(&adminv1.SetResourceAssignmentResponse{Assignment: result}), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, mapErr(err)
	}
	if device.CurrentGenerationID == nil || (device.State != stateActive && device.State != statePending) {
		return nil, mapErr(errDeviceRevoked)
	}
	generationID := *device.CurrentGenerationID
	head, err := q.LockServiceAssignment(ctx, generationID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, mapErr(err)
	}
	if (err == nil && head.ID.String() != req.Msg.GetExpectedAssignmentId()) || (errors.Is(err, pgx.ErrNoRows) && req.Msg.ExpectedAssignmentId != nil) {
		return nil, rpcError(connect.CodeAborted, "service_assignment_conflict")
	}
	capacity, err := q.ServiceDispatchCapacity(ctx, generationID)
	if err != nil {
		return nil, mapErr(err)
	}
	if capacity.Assignments >= 65536 {
		return nil, rpcError(connect.CodeResourceExhausted, "service_assignment_capacity")
	}
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, mapErr(err)
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
		retained, err := s.profiles.GetInTransaction(ctx, tx, profile, revision)
		if err != nil {
			return nil, profileError(err)
		}
		resolved, err := policy.Resolve(ctx, []policy.Assignment{{ProfileID: profile.String(), RevisionID: revision.String(), Spec: retained.GetSpec()}})
		if err != nil {
			return nil, profileError(err)
		}
		for _, item := range resolved {
			if item.State != policy.ResolutionReady {
				return nil, rpcError(connect.CodeFailedPrecondition, "resource_resolution_conflict")
			}
		}
		assignment.ProfileId, assignment.RevisionId, assignment.RevisionNumber, assignment.ProfileName = retained.GetProfileId(), retained.GetRevisionId(), retained.GetRevisionNumber(), retained.GetSpec().GetName()
		revisionID = &revision
		resources, err = orderedResources(retained.GetSpec().GetResources())
		if err != nil {
			return nil, mapErr(err)
		}
	}
	if resourceAdoptionRequired(resources) && consumption == nil {
		return nil, approvalError(identity.ErrApprovalRequired)
	}
	document, err := proto.Marshal(assignment)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := q.InsertServiceAssignment(ctx, devicedb.InsertServiceAssignmentParams{ID: id, DeviceID: deviceID, GenerationID: generationID, RequestID: requestID, RequestDigest: digest[:], ActorID: actor.ID, AuthorizationVersion: int64(approval.Version()), RevisionID: revisionID, Document: document, AssignedAt: timestamptz(now), ReconcileIntervalSeconds: int32(assignment.GetReconcileIntervalSeconds())}); err != nil {
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) && pgerr.Code == "23505" {
			return nil, mapErr(errIdempotencyConflict)
		}
		return nil, mapErr(err)
	}
	if err := insertResourceRows(ctx, q, id, resources); err != nil {
		return nil, mapErr(err)
	}
	if resourceAdoptionRequired(resources) {
		approvalID, err := uuid.Parse(req.Msg.GetApprovalId())
		if err != nil {
			return nil, approvalError(identity.ErrApprovalInvalid)
		}
		if err := q.SetResourceAssignmentAdoptionApproval(ctx, devicedb.SetResourceAssignmentAdoptionApprovalParams{ID: id, AdoptionApprovalID: &approvalID}); err != nil {
			return nil, mapErr(err)
		}
	}
	if head.ID != uuid.Nil {
		if err := q.RecordResourceReleases(ctx, devicedb.RecordResourceReleasesParams{NewAssignmentID: id, OldAssignmentID: head.ID, RequestedAt: timestamptz(now)}); err != nil {
			return nil, mapErr(err)
		}
	}
	if err := q.SetServiceAssignmentHead(ctx, devicedb.SetServiceAssignmentHeadParams{GenerationID: generationID, AssignmentID: id}); err != nil {
		return nil, mapErr(err)
	}
	action, err := q.GetOpenServiceAction(ctx, deviceID)
	if err == nil && len(action.StartGrantEnvelope) == 0 {
		if err := closeUnstartedResourceAction(ctx, q, &action, "assignment_changed", now); err != nil {
			return nil, mapErr(err)
		}
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, mapErr(err)
	}
	auditAction := "service_assignment.assign"
	if req.Msg.GetClear() {
		auditAction = "service_assignment.clear"
	}
	if err := dispatchAudit(ctx, q, &actor.ID, auditAction, id, req.Msg.GetReason()); err != nil {
		return nil, mapErr(err)
	}
	if err := s.lockActionApproval(ctx, tx, consumption, approval, identity.PermissionAssignResources); err != nil {
		return nil, approvalError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.SetResourceAssignmentResponse{Assignment: assignment}), nil
}

func (s *Service) GetDeviceResourceState(ctx context.Context, req *connect.Request[adminv1.GetDeviceResourceStateRequest]) (*connect.Response[adminv1.GetDeviceResourceStateResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionReadFleet)
	if err != nil {
		return nil, err
	}
	if err := s.acquire(ctx); err != nil {
		return nil, mapErr(err)
	}
	defer s.release()
	if req == nil || req.Msg == nil || s.rules.Validate(req.Msg) != nil {
		return nil, invalid("invalid_service_assignment")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	id, _ := uuid.Parse(req.Msg.GetDeviceId())
	device, err := lockDeviceScope(ctx, q, actor, identity.PermissionReadFleet, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, mapErr(err)
	}
	response := new(adminv1.GetDeviceResourceStateResponse)
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return nil, mapErr(err)
	}
	if device.CurrentGenerationID != nil {
		head, err := q.LockServiceAssignment(ctx, *device.CurrentGenerationID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, mapErr(err)
		}
		if err == nil {
			response.Assignment = new(adminv1.ResourceAssignment)
			if err := proto.Unmarshal(head.Document, response.Assignment); err != nil {
				return nil, mapErr(errInternalState)
			}
			resources, err := q.ListServiceResources(ctx, head.ID)
			if err != nil {
				return nil, mapErr(err)
			}
			dispositions := make(map[string]adminv1.ResourceDisposition, len(resources))
			for _, row := range resources {
				resource := new(policyv1.ProfileResource)
				if err := proto.Unmarshal(row.Document, resource); err != nil {
					return nil, mapErr(errInternalState)
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
				latest, err := q.LatestServiceAction(ctx, devicedb.LatestServiceActionParams{AssignmentID: head.ID, ResourceID: row.ResourceID})
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return nil, mapErr(err)
				}
				if err == nil {
					state.LatestAction, err = resourceActionSummary(latest)
					if err != nil {
						return nil, mapErr(err)
					}
				}
				state.LastVerifiedAt = protoTime(row.LastVerifiedAt)
				state.ObservedAt = protoTime(row.ObservedAt)
				state.Compliance = resourceCompliance(row, state, head, now)
				response.Resources = append(response.Resources, state)
			}
		}
		recent, err := q.RecentServiceActions(ctx, *device.CurrentGenerationID)
		if err != nil {
			return nil, mapErr(err)
		}
		for _, action := range recent {
			summary, err := resourceActionSummary(action)
			if err != nil {
				return nil, mapErr(err)
			}
			intent := new(agentv1.ResourceExecutionIntent)
			if err := proto.Unmarshal(action.IntentDocument, intent); err != nil {
				return nil, mapErr(errInternalState)
			}
			response.RecentActions = append(response.RecentActions, &adminv1.DeviceResourceAction{AssignmentId: action.AssignmentID.String(), ResourceId: action.ResourceID.String(), Ref: intent.GetDesired().GetRef(), Action: summary})
		}
		releases, err := q.ListResourceReleases(ctx, *device.CurrentGenerationID)
		if err != nil {
			return nil, mapErr(err)
		}
		for _, release := range releases {
			response.Releases = append(response.Releases, &adminv1.ResourceRelease{
				ReleaseId: release.ID.String(), Ref: &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind(release.ResourceKind), CanonicalKey: release.CanonicalKey},
				SourceAssignmentId: release.SourceAssignmentID.String(), SupersedingAssignmentId: release.SupersedingAssignmentID.String(),
				State: release.State, Reason: release.Reason, RequestedAt: protoTime(release.RequestedAt), CompletedAt: protoTime(release.CompletedAt),
			})
		}
	}
	encoded, err := protojson.Marshal(response)
	if err != nil {
		return nil, mapErr(err)
	}
	if len(encoded) > maxMessageBytes || proto.Size(response) > maxMessageBytes {
		return nil, rpcError(connect.CodeResourceExhausted, "service_state_response_capacity")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(response), nil
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
			return nil, errInternalState
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

func resourceActionSummary(action devicedb.ResourceAction) (*adminv1.ServiceActionSummary, error) {
	revision, err := resourceActionRevision(action)
	if err != nil {
		return nil, err
	}
	summary := &adminv1.ServiceActionSummary{ActionId: action.ID.String(), ResourceSequence: uint64(action.ResourceSequence), IssuedAt: protoTime(action.IssuedAt), ExpiresAt: protoTime(action.ExpiresAt), StartAuthorizedAt: protoTime(action.StartAuthorizedAt), ClosedReason: action.ClosedReason, ClosedAt: protoTime(action.ClosedAt), ActionRevision: revision, AttestedAt: protoTime(action.AttestedAt), ReceivedAt: protoTime(action.ReceivedAt)}
	if len(action.StatusDocument) != 0 {
		summary.Status = new(agentv1.ResourceExecutionStatus)
		if err := proto.Unmarshal(action.StatusDocument, summary.Status); err != nil {
			return nil, errInternalState
		}
	}
	return summary, nil
}
