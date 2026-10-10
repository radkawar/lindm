package device

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/devicedb"
)

func (s *Service) applyProvisioningMetadata(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID, assignment *adminv1.CreateProvisioningTokenRequest) error {
	metadata := assignment.GetMetadata()
	if metadata != nil {
		encoded, err := protojson.Marshal(metadata)
		if err != nil {
			return err
		}
		var owner *uuid.UUID
		if metadata.GetOwnerPrincipalId() != "" {
			id, _ := uuid.Parse(metadata.GetOwnerPrincipalId())
			owner = &id
		}
		if err := q.SetDeviceMetadata(ctx, devicedb.SetDeviceMetadataParams{ID: deviceID, Metadata: encoded, OwnerPrincipalID: owner}); err != nil {
			return err
		}
		if err := q.InsertDeviceLabels(ctx, devicedb.InsertDeviceLabelsParams{DeviceID: deviceID, Labels: metadata.GetLabels()}); err != nil {
			return err
		}
	}
	for _, value := range assignment.GetGroupIds() {
		group, _ := uuid.Parse(value)
		if err := q.AddProvisioningGroupMembership(ctx, devicedb.AddProvisioningGroupMembershipParams{GroupID: group, DeviceID: deviceID}); err != nil {
			return err
		}
	}
	return nil
}

// The immutable profile revision is copied to the normal service dispatcher, not
// a second execution mechanism. No head exists while approval is pending.
func (s *Service) activateProvisioningProfile(ctx context.Context, tx pgx.Tx, token devicedb.ProvisioningToken, receipt devicedb.ProvisioningEnrollment, assignment *adminv1.CreateProvisioningTokenRequest) error {
	if len(assignment.GetProfileRevisionIds()) == 0 {
		return nil
	}
	q := devicedb.New(tx)
	revision, _ := uuid.Parse(assignment.GetProfileRevisionIds()[0])
	profile, err := q.ProvisioningProfileIdentity(ctx, revision)
	if err != nil {
		return err
	}
	retained, err := s.profiles.GetInTransaction(ctx, tx, profile, revision)
	if err != nil {
		return profileError(err)
	}
	resources, err := orderedServiceResources(retained.GetSpec().GetResources())
	if err != nil {
		return err
	}
	now, err := dispatchClock(ctx, q)
	if err != nil {
		return err
	}
	id := uuid.New()
	document, err := proto.Marshal(&adminv1.ResourceAssignment{AssignmentId: id.String(), DeviceId: receipt.DeviceID.String(), EnrollmentGeneration: receipt.GenerationID.String(), ActorId: token.CreatedBy.String(), AssignedAt: timestamppb.New(now), Reason: token.Reason, ReconcileIntervalSeconds: 900, ProfileId: retained.GetProfileId(), RevisionId: retained.GetRevisionId(), RevisionNumber: retained.GetRevisionNumber(), ProfileName: retained.GetSpec().GetName()})
	if err != nil {
		return err
	}
	if err := q.InsertServiceAssignment(ctx, devicedb.InsertServiceAssignmentParams{ID: id, DeviceID: receipt.DeviceID, GenerationID: receipt.GenerationID, RequestID: receipt.TransactionID, RequestDigest: receipt.CsrSha256, ActorID: token.CreatedBy, AuthorizationVersion: token.AuthorizationVersion, RevisionID: &revision, Document: document, AssignedAt: timestamptz(now), ReconcileIntervalSeconds: 900}); err != nil {
		return err
	}
	if err := insertResourceRows(ctx, q, id, resources); err != nil {
		return err
	}
	if err := q.SetServiceAssignmentHead(ctx, devicedb.SetServiceAssignmentHeadParams{GenerationID: receipt.GenerationID, AssignmentID: id}); err != nil {
		return err
	}
	return insertAudit(ctx, q, &token.CreatedBy, "service_assignment.assign", id.String(), token.Reason)
}
