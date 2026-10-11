package dispatch

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/resource"
	"lindm/internal/targeting"
)

// The cache lives for one report transaction. Equal candidate sets reuse the
// canonical result, while effective heads are always read for the actual device.
func (s *Service) targetImpactResolver() targeting.ImpactResolver {
	revisions := &targetRevisionCache{revisions: make(map[uuid.UUID]*adminv1.ProfileRevision)}
	resolutions := make(map[[32]byte]*policyv1.TargetResolution)
	retainedBytes := 0
	return func(ctx context.Context, tx pgx.Tx, generation *uuid.UUID, candidates []*policyv1.TargetCandidate) (*policyv1.TargetResolution, *policyv1.TargetResolution, error) {
		b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&policyv1.TargetPreview{Candidates: candidates})
		if err != nil {
			return nil, nil, err
		}
		key := sha256.Sum256(b)
		proposed := resolutions[key]
		if proposed == nil {
			proposed, err = s.resolveTargetCandidatesCached(ctx, tx, candidates, revisions)
			if err != nil {
				return nil, nil, err
			}
			size := proto.Size(proposed)
			if retainedBytes+size <= 8<<20 && len(resolutions) < 10000 {
				resolutions[key] = proposed
				retainedBytes += size
			}
		}
		current := new(policyv1.TargetResolution)
		if generation == nil {
			return current, proposed, nil
		}
		q := devicedb.New(tx)
		head, err := q.GetResourceAssignment(ctx, *generation)
		if errors.Is(err, pgx.ErrNoRows) {
			return current, proposed, nil
		}
		if err != nil {
			return nil, nil, err
		}
		rows, err := q.ListAssignmentResources(ctx, head.ID)
		if err != nil {
			return nil, nil, err
		}
		for _, row := range rows {
			item := new(policyv1.ProfileResource)
			if err := proto.Unmarshal(row.Document, item); err != nil {
				return nil, nil, err
			}
			capability, err := resource.Capability(item.GetDesired().GetRef().GetKind())
			if err != nil {
				return nil, nil, err
			}
			unsupported := ResourceDispatchUnsupported(item)
			resolved := &policyv1.ResolvedResource{Ref: item.GetDesired().GetRef(), Resource: item, Disposition: policyv1.ResourceResolutionDisposition_RESOURCE_RESOLUTION_DISPOSITION_READY, CapabilityId: capability, DispatchSupported: unsupported == "", Reason: unsupported}
			if head.BlockedReason != "" {
				resolved.Disposition = policyv1.ResourceResolutionDisposition_RESOURCE_RESOLUTION_DISPOSITION_BLOCKED
				resolved.Reason = head.BlockedReason
			}
			current.Resources = append(current.Resources, resolved)
		}
		return current, proposed, nil
	}
}
