package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sort"

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
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func (s *Service) SetServiceAssignment(ctx context.Context, req *connect.Request[adminv1.SetServiceAssignmentRequest]) (*connect.Response[adminv1.SetServiceAssignmentResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	actor, err := s.require(ctx, identity.PermissionAssignServices)
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
	approval, err := s.identity.AuthorizeFresh(ctx, actor.ID, identity.PermissionAssignServices)
	if err != nil {
		return nil, executionError(err)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionAssignServices); err != nil {
		return nil, executionError(err)
	}
	q := devicedb.New(tx)
	deviceID, _ := uuid.Parse(req.Msg.GetDeviceId())
	device, err := q.GetDeviceForUpdate(ctx, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, mapErr(err)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(req.Msg)
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
		result := new(adminv1.ServiceAssignment)
		if err := proto.Unmarshal(previous.Document, result); err != nil {
			return nil, mapErr(errInternalState)
		}
		if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionAssignServices); err != nil {
			return nil, executionError(err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, mapErr(err)
		}
		return noStore(&adminv1.SetServiceAssignmentResponse{Assignment: result}), nil
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
	assignment := &adminv1.ServiceAssignment{AssignmentId: id.String(), DeviceId: deviceID.String(), EnrollmentGeneration: generationID.String(), ActorId: actor.ID.String(), AssignedAt: timestamppb.New(now), Reason: req.Msg.GetReason()}
	var revisionID *uuid.UUID
	var resources []*policyv1.ServiceProfileResource
	if target := req.Msg.GetTarget(); target != nil {
		profile, _ := uuid.Parse(target.GetProfileId())
		revision, _ := uuid.Parse(target.GetRevisionId())
		retained, err := s.profiles.GetInTransaction(ctx, tx, profile, revision)
		if err != nil {
			return nil, profileError(err)
		}
		assignment.ProfileId, assignment.RevisionId, assignment.RevisionNumber, assignment.ProfileName = retained.GetProfileId(), retained.GetRevisionId(), retained.GetRevisionNumber(), retained.GetSpec().GetName()
		revisionID = &revision
		resources, err = orderedServiceResources(retained.GetSpec().GetResources())
		if err != nil {
			return nil, mapErr(err)
		}
	}
	document, err := proto.Marshal(assignment)
	if err != nil {
		return nil, mapErr(err)
	}
	if err := q.InsertServiceAssignment(ctx, devicedb.InsertServiceAssignmentParams{ID: id, DeviceID: deviceID, GenerationID: generationID, RequestID: requestID, RequestDigest: digest[:], ActorID: actor.ID, AuthorizationVersion: int64(approval.Version()), RevisionID: revisionID, Document: document, AssignedAt: timestamptz(now)}); err != nil {
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) && pgerr.Code == "23505" {
			return nil, mapErr(errIdempotencyConflict)
		}
		return nil, mapErr(err)
	}
	for i, resource := range resources {
		encoded, err := proto.Marshal(resource)
		if err != nil {
			return nil, mapErr(err)
		}
		resourceID, _ := uuid.Parse(resource.GetResourceId())
		if err := q.InsertServiceResource(ctx, devicedb.InsertServiceResourceParams{AssignmentID: id, ResourceID: resourceID, UnitName: resource.GetDesired().GetUnit(), Position: int32(i), Document: encoded}); err != nil {
			return nil, mapErr(err)
		}
	}
	if err := q.SetServiceAssignmentHead(ctx, devicedb.SetServiceAssignmentHeadParams{GenerationID: generationID, AssignmentID: id}); err != nil {
		return nil, mapErr(err)
	}
	action, err := q.GetOpenServiceAction(ctx, deviceID)
	if err == nil && len(action.StartGrantEnvelope) == 0 {
		if err := closeUnstartedServiceAction(ctx, q, action, "assignment_changed", now); err != nil {
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
	if err := s.identity.LockAuthorization(ctx, tx, approval, identity.PermissionAssignServices); err != nil {
		return nil, executionError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}
	return noStore(&adminv1.SetServiceAssignmentResponse{Assignment: assignment}), nil
}

func (s *Service) GetDeviceServiceState(ctx context.Context, req *connect.Request[adminv1.GetDeviceServiceStateRequest]) (*connect.Response[adminv1.GetDeviceServiceStateResponse], error) {
	ctx, cancel := bound(ctx)
	defer cancel()
	if _, err := s.require(ctx, identity.PermissionReadFleet); err != nil {
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
	device, err := q.GetDeviceForUpdate(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, mapErr(err)
	}
	response := new(adminv1.GetDeviceServiceStateResponse)
	if device.CurrentGenerationID != nil {
		head, err := q.LockServiceAssignment(ctx, *device.CurrentGenerationID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, mapErr(err)
		}
		if err == nil {
			response.Assignment = new(adminv1.ServiceAssignment)
			if err := proto.Unmarshal(head.Document, response.Assignment); err != nil {
				return nil, mapErr(errInternalState)
			}
			resources, err := q.ListServiceResources(ctx, head.ID)
			if err != nil {
				return nil, mapErr(err)
			}
			dispositions := make(map[string]adminv1.ServiceResourceDisposition, len(resources))
			for _, row := range resources {
				resource := new(policyv1.ServiceProfileResource)
				if err := proto.Unmarshal(row.Document, resource); err != nil {
					return nil, mapErr(errInternalState)
				}
				state := &adminv1.ServiceResourceState{ResourceId: row.ResourceID.String(), Desired: resource.GetDesired(), DependsOn: resource.GetDependsOn(), Disposition: adminv1.ServiceResourceDisposition(row.Disposition), Reason: row.Reason}
				if state.Disposition == adminv1.ServiceResourceDisposition_SERVICE_RESOURCE_DISPOSITION_PENDING {
					if head.BlockedReason != "" {
						state.Disposition = adminv1.ServiceResourceDisposition_SERVICE_RESOURCE_DISPOSITION_BLOCKED
						state.Reason = head.BlockedReason
					} else {
						for _, dependency := range state.DependsOn {
							d := dispositions[dependency]
							if d == adminv1.ServiceResourceDisposition_SERVICE_RESOURCE_DISPOSITION_ATTENTION || d == adminv1.ServiceResourceDisposition_SERVICE_RESOURCE_DISPOSITION_BLOCKED {
								state.Disposition = adminv1.ServiceResourceDisposition_SERVICE_RESOURCE_DISPOSITION_BLOCKED
								state.Reason = "dependency_attention"
								break
							}
							if d != adminv1.ServiceResourceDisposition_SERVICE_RESOURCE_DISPOSITION_SUCCEEDED {
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
					state.LatestAction, err = serviceActionSummary(latest)
					if err != nil {
						return nil, mapErr(err)
					}
				}
				response.Resources = append(response.Resources, state)
			}
		}
		recent, err := q.RecentServiceActions(ctx, *device.CurrentGenerationID)
		if err != nil {
			return nil, mapErr(err)
		}
		for _, action := range recent {
			summary, err := serviceActionSummary(action)
			if err != nil {
				return nil, mapErr(err)
			}
			intent := new(agentv1.ServiceExecutionIntent)
			if err := proto.Unmarshal(action.IntentDocument, intent); err != nil {
				return nil, mapErr(errInternalState)
			}
			response.RecentActions = append(response.RecentActions, &adminv1.DeviceServiceAction{AssignmentId: action.AssignmentID.String(), ResourceId: action.ResourceID.String(), Unit: intent.GetDesired().GetUnit(), Action: summary})
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
func orderedServiceResources(resources []*policyv1.ServiceProfileResource) ([]*policyv1.ServiceProfileResource, error) {
	pending := append([]*policyv1.ServiceProfileResource(nil), resources...)
	sort.Slice(pending, func(i, j int) bool { return pending[i].GetDesired().GetUnit() < pending[j].GetDesired().GetUnit() })
	ordered := make([]*policyv1.ServiceProfileResource, 0, len(pending))
	done := make(map[string]bool, len(pending))
	for len(pending) != 0 {
		found := false
		for i, resource := range pending {
			eligible := true
			for _, dependency := range resource.GetDependsOn() {
				if !done[dependency] {
					eligible = false
					break
				}
			}
			if !eligible {
				continue
			}
			ordered = append(ordered, resource)
			done[resource.GetResourceId()] = true
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

func serviceActionSummary(action devicedb.ServiceAction) (*adminv1.ServiceActionSummary, error) {
	revision, err := serviceActionRevision(action)
	if err != nil {
		return nil, err
	}
	summary := &adminv1.ServiceActionSummary{ActionId: action.ID.String(), ResourceSequence: uint64(action.ResourceSequence), IssuedAt: protoTime(action.IssuedAt), ExpiresAt: protoTime(action.ExpiresAt), StartAuthorizedAt: protoTime(action.StartAuthorizedAt), ClosedReason: action.ClosedReason, ClosedAt: protoTime(action.ClosedAt), ActionRevision: revision, AttestedAt: protoTime(action.AttestedAt), ReceivedAt: protoTime(action.ReceivedAt)}
	if len(action.StatusDocument) != 0 {
		summary.Status = new(agentv1.ServiceExecutionStatus)
		if err := proto.Unmarshal(action.StatusDocument, summary.Status); err != nil {
			return nil, errInternalState
		}
	}
	return summary, nil
}
