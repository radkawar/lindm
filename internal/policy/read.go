package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/policy/profiledb"
)

// Get reads either a captured catalog head or the exact requested revision.
// Subsequent resource queries read append-only rows, never a newer head.
func (s *Store) Get(ctx context.Context, profileID uuid.UUID, revisionID *uuid.UUID) (*adminv1.ServiceProfileRevision, error) {
	if profileID == uuid.Nil || (revisionID != nil && *revisionID == uuid.Nil) {
		return nil, ErrProfileRejected
	}
	return s.readRevision(ctx, profiledb.New(s.pool), profileID, revisionID)
}

// GetInTransaction reads an immutable revision using the caller's transaction.
func (s *Store) GetInTransaction(ctx context.Context, tx pgx.Tx, profileID, revisionID uuid.UUID) (*adminv1.ServiceProfileRevision, error) {
	if tx == nil || profileID == uuid.Nil || revisionID == uuid.Nil {
		return nil, ErrProfileRejected
	}
	return s.readRevision(ctx, profiledb.New(tx), profileID, &revisionID)
}

func (s *Store) readRevision(ctx context.Context, q *profiledb.Queries, profileID uuid.UUID, revisionID *uuid.UUID) (*adminv1.ServiceProfileRevision, error) {
	row, err := q.GetProfileRevision(ctx, profiledb.GetProfileRevisionParams{ProfileID: profileID, RevisionID: revisionID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrProfileNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.readRevisionRow(ctx, q, row)
}

func (s *Store) readRevisionRow(ctx context.Context, q *profiledb.Queries, row profiledb.ServiceProfileRevision) (*adminv1.ServiceProfileRevision, error) {
	if !validRevisionMetadata(row) {
		return nil, ErrProfileCorrupt
	}
	resources, err := q.ListProfileResources(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	if len(resources) != int(row.ResourceCount) || len(resources) > 64 {
		return nil, ErrProfileCorrupt
	}
	dependencies, err := q.ListProfileDependencies(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	if len(dependencies) > 4032 {
		return nil, ErrProfileCorrupt
	}
	spec := &policyv1.ServiceProfileSpec{Name: row.Name, Description: row.Description, Resources: make([]*policyv1.ServiceProfileResource, 0, len(resources))}
	byID := make(map[uuid.UUID]*policyv1.ServiceProfileResource, len(resources))
	for _, source := range resources {
		resource := &policyv1.ServiceProfileResource{ResourceId: source.ResourceID.String(), Desired: &agentv1.ServiceDesiredState{Unit: source.UnitName, Runtime: agentv1.ServiceRuntimeState(source.RuntimeState), Enablement: agentv1.ServiceEnablement(source.EnablementState)}}
		spec.Resources = append(spec.Resources, resource)
		byID[source.ResourceID] = resource
	}
	for _, source := range dependencies {
		resource, ok := byID[source.ResourceID]
		if !ok {
			return nil, ErrProfileCorrupt
		}
		if _, ok := byID[source.DependencyID]; !ok {
			return nil, ErrProfileCorrupt
		}
		resource.DependsOn = append(resource.DependsOn, source.DependencyID.String())
	}
	if err := Validate(ctx, spec); err != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, ErrProfileCorrupt
	}
	// SQL orders UUIDs identically to their canonical spelling. No second clone or
	// sort is needed to recover the exact canonical revision digest.
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(spec)
	if err != nil {
		return nil, ErrProfileCorrupt
	}
	digest := sha256.Sum256(encoded)
	if !bytes.Equal(digest[:], row.SpecDigest) {
		return nil, ErrProfileCorrupt
	}
	return &adminv1.ServiceProfileRevision{ProfileId: row.ProfileID.String(), RevisionId: row.ID.String(), RevisionNumber: uint64(row.RevisionNumber), Spec: spec, ActorId: row.ActorID.String(), PublishedAt: timestamppb.New(row.PublishedAt.Time), SpecSha256: row.SpecDigest}, nil
}

// List returns metadata only, keeping page work independent of dependency-graph
// density. The cursor identifies a catalog position, not a frozen deployment.
func (s *Store) List(ctx context.Context, after uuid.UUID, pageSize int32) ([]*adminv1.ServiceProfileSummary, uuid.UUID, error) {
	if pageSize < 1 || pageSize > 100 {
		return nil, uuid.Nil, ErrProfileRejected
	}
	rows, err := profiledb.New(s.pool).ListProfileHeads(ctx, profiledb.ListProfileHeadsParams{AfterID: after, PageLimit: pageSize + 1})
	if err != nil {
		return nil, uuid.Nil, err
	}
	next := uuid.Nil
	if len(rows) > int(pageSize) {
		rows = rows[:pageSize]
		next = rows[len(rows)-1].ProfileID
	}
	result := make([]*adminv1.ServiceProfileSummary, 0, len(rows))
	for _, row := range rows {
		if !validRevisionMetadata(row) {
			return nil, uuid.Nil, ErrProfileCorrupt
		}
		result = append(result, &adminv1.ServiceProfileSummary{ProfileId: row.ProfileID.String(), RevisionId: row.ID.String(), RevisionNumber: uint64(row.RevisionNumber), Name: row.Name, Description: row.Description, ResourceCount: uint32(row.ResourceCount), ActorId: row.ActorID.String(), PublishedAt: timestamppb.New(row.PublishedAt.Time), SpecSha256: row.SpecDigest})
	}
	return result, next, nil
}

func validRevisionMetadata(row profiledb.ServiceProfileRevision) bool {
	return row.ID != uuid.Nil && row.ProfileID != uuid.Nil && row.ActorID != uuid.Nil && row.RevisionNumber > 0 && row.ResourceCount >= 1 && row.ResourceCount <= 64 && len(row.SpecDigest) == sha256.Size && finiteProfileTime(row.PublishedAt)
}
