// SPDX-License-Identifier: Apache-2.0

package dispatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"lindm/internal/auditkind"
	"lindm/internal/device/core"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/policy"
	"lindm/internal/resource"
	"lindm/internal/rpcreason"
)

func (s *Service) resolveTargetCandidates(ctx context.Context, tx pgx.Tx, candidates []*policyv1.TargetCandidate) (*policyv1.TargetResolution, error) {
	return s.resolveTargetCandidatesCached(ctx, tx, candidates, &targetRevisionCache{revisions: make(map[uuid.UUID]*adminv1.ProfileRevision)})
}

type targetRevisionCache struct {
	revisions map[uuid.UUID]*adminv1.ProfileRevision
	bytes     int
}

func (s *Service) resolveTargetCandidatesCached(ctx context.Context, tx pgx.Tx, candidates []*policyv1.TargetCandidate, cache *targetRevisionCache) (*policyv1.TargetResolution, error) {
	assignments := make([]policy.Assignment, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.GetMatch() != policyv1.TargetMatch_TARGET_MATCH_INCLUDED {
			continue
		}
		id, err := uuid.Parse(candidate.GetAssignment().GetProfileRevisionId())
		if err != nil {
			return nil, err
		}
		revision := cache.revisions[id]
		if revision == nil {
			revision, err = s.Profiles.GetRevisionInTransaction(ctx, tx, id)
			if err != nil {
				return nil, err
			}
			cache.bytes += proto.Size(revision.GetSpec())
			if cache.bytes > core.MaxMessageBytes {
				return nil, rpcreason.Error(connect.CodeResourceExhausted, "target_resolution_capacity")
			}
			cache.revisions[id] = revision
		}
		assignments = append(assignments, policy.Assignment{ProfileID: revision.GetProfileId(), RevisionID: revision.GetRevisionId(), Priority: candidate.GetAssignment().GetPriority(), Spec: revision.GetSpec()})
	}
	resolved, err := policy.Resolve(ctx, assignments)
	if err != nil {
		return nil, err
	}
	out := &policyv1.TargetResolution{}
	for _, item := range resolved {
		capability, err := resource.Capability(item.Ref.GetKind())
		if err != nil {
			return nil, err
		}
		if item.Resource != nil {
			refDigest, err := resource.RefDigest(item.Ref)
			if err != nil {
				return nil, err
			}
			// Source resource UUIDs are profile-local. Effective identities are derived
			// from canonical refs so heterogeneous contributors cannot collide in a head.
			item.Resource.ResourceId = uuid.NewSHA1(uuid.NameSpaceOID, refDigest[:]).String()
		}
		unsupported := ResourceDispatchUnsupported(item.Resource)
		result := &policyv1.ResolvedResource{Ref: item.Ref, Resource: item.Resource, Disposition: policyv1.ResourceResolutionDisposition(item.State), CapabilityId: capability, DispatchSupported: unsupported == ""}
		if item.Reason != policy.ReasonNone {
			result.Reason = fmt.Sprintf("resolution_reason_%d", item.Reason)
		}
		if !result.DispatchSupported && result.Reason == "" {
			result.Reason = unsupported
		}
		for _, contributor := range item.Contributors {
			result.ContributingRevisionIds = append(result.ContributingRevisionIds, contributor.RevisionID)
		}
		for _, overridden := range item.Overridden {
			result.OverriddenRevisionIds = append(result.OverriddenRevisionIds, overridden.RevisionID)
		}
		out.Resources = append(out.Resources, result)
	}
	return out, nil
}

// reason is the activation's human reason (a rollout's or an administrator's),
// shown on the device as why its settings changed.
func (s *Service) activateTargetPreview(ctx context.Context, tx pgx.Tx, preview *policyv1.TargetPreview, actor uuid.UUID, authorizationVersion uint64, adoptionApprovalID, reason string) error {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(preview.GetResolution())
	if err != nil {
		return err
	}
	hash := sha256.New()
	hash.Write([]byte("lindm.targeting.resolution.v1\x00"))
	hash.Write(encoded)
	if !bytes.Equal(hash.Sum(nil), preview.GetResolutionSha256()) {
		return core.ErrInternalState
	}
	resources := make([]*policyv1.ProfileResource, 0, len(preview.GetResolution().GetResources()))
	for _, item := range preview.GetResolution().GetResources() {
		if item.GetDisposition() != policyv1.ResourceResolutionDisposition_RESOURCE_RESOLUTION_DISPOSITION_READY || item.GetResource() == nil {
			return rpcreason.Error(connect.CodeFailedPrecondition, "resource_resolution_conflict")
		}
		resources = append(resources, proto.CloneOf(item.GetResource()))
	}
	if resourceAdoptionRequired(resources) && adoptionApprovalID == "" {
		return rpcreason.Error(connect.CodePermissionDenied, "approval_required")
	}
	ordered, err := orderedResources(resources)
	if err != nil {
		return err
	}
	id, err := uuid.Parse(preview.GetPreviewId())
	if err != nil {
		return err
	}
	deviceID, err := uuid.Parse(preview.GetDeviceId())
	if err != nil {
		return err
	}
	generation, err := uuid.Parse(preview.GetGenerationId())
	if err != nil {
		return err
	}
	q := devicedb.New(tx)
	head, headErr := q.LockResourceAssignment(ctx, generation)
	if headErr != nil && !errors.Is(headErr, pgx.ErrNoRows) {
		return headErr
	}
	if headErr == nil && head.ID == id {
		return nil
	}
	now, err := core.DispatchClock(ctx, q)
	if err != nil {
		return err
	}
	assignment := &adminv1.ResourceAssignment{AssignmentId: id.String(), DeviceId: deviceID.String(), EnrollmentGeneration: generation.String(), ActorId: actor.String(), AssignedAt: timestamppb.New(now), Reason: reason, ReconcileIntervalSeconds: 900}
	document, err := proto.Marshal(assignment)
	if err != nil {
		return err
	}
	if err := q.InsertResourceAssignment(ctx, devicedb.InsertResourceAssignmentParams{ID: id, DeviceID: deviceID, GenerationID: generation, RequestID: id, RequestDigest: preview.GetPreviewSha256(), ActorID: actor, AuthorizationVersion: int64(authorizationVersion), Document: document, AssignedAt: core.Timestamptz(now), ReconcileIntervalSeconds: 900}); err != nil {
		return err
	}
	if err := insertResourceRows(ctx, q, id, generation, ordered); err != nil {
		return err
	}
	if resourceAdoptionRequired(resources) {
		approvalID, err := uuid.Parse(adoptionApprovalID)
		if err != nil {
			return rpcreason.Error(connect.CodePermissionDenied, "approval_invalid")
		}
		if err := q.SetResourceAssignmentAdoptionApproval(ctx, devicedb.SetResourceAssignmentAdoptionApprovalParams{ID: id, AdoptionApprovalID: &approvalID}); err != nil {
			return err
		}
	}
	if headErr == nil {
		if err := q.RecordResourceReleases(ctx, devicedb.RecordResourceReleasesParams{NewAssignmentID: id, OldAssignmentID: head.ID, RequestedAt: core.Timestamptz(now)}); err != nil {
			return err
		}
	}
	if err := q.SetResourceAssignmentHead(ctx, devicedb.SetResourceAssignmentHeadParams{GenerationID: generation, AssignmentID: id}); err != nil {
		return err
	}
	action, err := q.GetOpenResourceAction(ctx, deviceID)
	if err == nil && len(action.StartGrantEnvelope) == 0 {
		if err := closeUnstartedResourceAction(ctx, q, &action, "assignment_changed", now); err != nil {
			return err
		}
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return core.DeviceAudit(ctx, q, &actor, auditkind.ResourceAssignmentAssign, id.String(), deviceID, "", "source", "target_preview_activation")
}
