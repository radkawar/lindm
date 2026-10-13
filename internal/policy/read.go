package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/policy/profiledb"
)

// Get reads either a captured catalog head or the exact requested revision.
// Subsequent resource queries read append-only rows, never a newer head.
func (s *Store) Get(ctx context.Context, profileID uuid.UUID, revisionID *uuid.UUID) (*adminv1.ProfileRevision, error) {
	if profileID == uuid.Nil || (revisionID != nil && *revisionID == uuid.Nil) {
		return nil, ErrProfileRejected
	}
	q := profiledb.New(s.pool)
	revision, err := s.readRevision(ctx, q, profileID, revisionID)
	if err != nil {
		return nil, err
	}
	names, err := actorNames(ctx, q, revision.GetActorId())
	if err != nil {
		return nil, err
	}
	revision.ActorDisplayName = names[revision.GetActorId()]
	return revision, nil
}

// actorNames projects the current account labels of publishers for readers.
// Labels are mutable display context; actor IDs remain the audited identity.
func actorNames(ctx context.Context, q *profiledb.Queries, ids ...string) (map[string]string, error) {
	parsed := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if actor, err := uuid.Parse(id); err == nil && !slices.Contains(parsed, actor) {
			parsed = append(parsed, actor)
		}
	}
	labels, err := q.ListProfileActorNames(ctx, parsed)
	if err != nil {
		return nil, err
	}
	names := make(map[string]string, len(labels))
	for _, label := range labels {
		names[label.ID.String()] = label.DisplayName
	}
	return names, nil
}

// GetInTransaction reads an immutable revision using the caller's transaction.
func (s *Store) GetInTransaction(ctx context.Context, tx pgx.Tx, profileID, revisionID uuid.UUID) (*adminv1.ProfileRevision, error) {
	if tx == nil || profileID == uuid.Nil || revisionID == uuid.Nil {
		return nil, ErrProfileRejected
	}
	return s.readRevision(ctx, profiledb.New(tx), profileID, &revisionID)
}

// GetRevisionInTransaction resolves a retained revision identity without
// consulting a mutable catalog head.
func (s *Store) GetRevisionInTransaction(ctx context.Context, tx pgx.Tx, revisionID uuid.UUID) (*adminv1.ProfileRevision, error) {
	if tx == nil || revisionID == uuid.Nil {
		return nil, ErrProfileRejected
	}
	q := profiledb.New(tx)
	row, err := q.GetRetainedProfileRevision(ctx, revisionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrProfileNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.readRevisionRow(ctx, q, row)
}

func (s *Store) readRevision(ctx context.Context, q *profiledb.Queries, profileID uuid.UUID, revisionID *uuid.UUID) (*adminv1.ProfileRevision, error) {
	row, err := q.GetProfileRevision(ctx, profiledb.GetProfileRevisionParams{ProfileID: profileID, RevisionID: revisionID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrProfileNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.readRevisionRow(ctx, q, row)
}

func (s *Store) readRevisionRow(ctx context.Context, q *profiledb.Queries, row profiledb.ProfileRevision) (*adminv1.ProfileRevision, error) {
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
	spec := &policyv1.ResourceProfile{Name: row.Name, Description: row.Description, Resources: make([]*policyv1.ProfileResource, 0, len(resources))}
	byID := make(map[uuid.UUID]*policyv1.ProfileResource, len(resources))
	for _, source := range resources {
		resource := &policyv1.ProfileResource{}
		if err := proto.Unmarshal(source.ResourceProto, resource); err != nil {
			return nil, ErrProfileCorrupt
		}
		ref := resource.GetDesired().GetRef()
		if resource.GetResourceId() != source.ResourceID.String() || len(resource.GetDependsOn()) != 0 ||
			int16(ref.GetKind()) != source.ResourceKind || ref.GetCanonicalKey() != source.CanonicalKey {
			return nil, ErrProfileCorrupt
		}
		spec.Resources = append(spec.Resources, resource)
		byID[source.ResourceID] = resource
	}
	for _, source := range dependencies {
		resource, ok := byID[source.ResourceID]
		if !ok {
			return nil, ErrProfileCorrupt
		}
		resource.DependsOn = append(resource.DependsOn, &policyv1.ResourceDependency{
			Ref:       &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind(source.DependencyKind), CanonicalKey: source.DependencyKey},
			Condition: policyv1.DependencyCondition(source.Condition),
		})
	}
	for _, resource := range spec.Resources {
		slices.SortFunc(resource.DependsOn, compareDependency)
	}
	if err := Validate(ctx, spec); err != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, ErrProfileCorrupt
	}
	// Recover canonical dependency ordering before checking the revision digest.
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(spec)
	if err != nil {
		return nil, ErrProfileCorrupt
	}
	digest := profileDigest(encoded)
	if !bytes.Equal(digest[:], row.SpecDigest) {
		return nil, ErrProfileCorrupt
	}
	return &adminv1.ProfileRevision{ProfileId: row.ProfileID.String(), RevisionId: row.ID.String(), RevisionNumber: uint64(row.RevisionNumber), Spec: spec, ActorId: row.ActorID.String(), PublishedAt: timestamppb.New(row.PublishedAt.Time), SpecSha256: row.SpecDigest}, nil
}

// List returns metadata only, keeping page work independent of dependency-graph
// density. The cursor identifies a catalog position, not a frozen deployment.
func (s *Store) List(ctx context.Context, after uuid.UUID, nameSearch string, pageSize int32) ([]*adminv1.ProfileSummary, uuid.UUID, error) {
	if pageSize < 1 || pageSize > 100 {
		return nil, uuid.Nil, ErrProfileRejected
	}
	rows, err := profiledb.New(s.pool).ListProfileHeads(ctx, profiledb.ListProfileHeadsParams{AfterID: after, NameSearch: nameSearch, PageLimit: pageSize + 1})
	if err != nil {
		return nil, uuid.Nil, err
	}
	next := uuid.Nil
	if len(rows) > int(pageSize) {
		rows = rows[:pageSize]
		next = rows[len(rows)-1].ProfileID
	}
	result := make([]*adminv1.ProfileSummary, 0, len(rows))
	for _, row := range rows {
		if !validRevisionMetadata(row) {
			return nil, uuid.Nil, ErrProfileCorrupt
		}
		result = append(result, &adminv1.ProfileSummary{ProfileId: row.ProfileID.String(), RevisionId: row.ID.String(), RevisionNumber: uint64(row.RevisionNumber), Name: row.Name, Description: row.Description, ResourceCount: uint32(row.ResourceCount), ActorId: row.ActorID.String(), PublishedAt: timestamppb.New(row.PublishedAt.Time), SpecSha256: row.SpecDigest})
	}
	if err := nameSummaryActors(ctx, profiledb.New(s.pool), result); err != nil {
		return nil, uuid.Nil, err
	}
	return result, next, nil
}

func nameSummaryActors(ctx context.Context, q *profiledb.Queries, summaries []*adminv1.ProfileSummary) error {
	ids := make([]string, 0, len(summaries))
	for _, summary := range summaries {
		ids = append(ids, summary.GetActorId())
	}
	names, err := actorNames(ctx, q, ids...)
	if err != nil {
		return err
	}
	for _, summary := range summaries {
		summary.ActorDisplayName = names[summary.GetActorId()]
	}
	return nil
}

// ListRevisions returns retained metadata newest first, without loading resources.
func (s *Store) ListRevisions(ctx context.Context, profileID uuid.UUID, before int64, pageSize int32) ([]*adminv1.ProfileSummary, int64, error) {
	if profileID == uuid.Nil || before < 0 || pageSize < 1 || pageSize > 200 {
		return nil, 0, ErrProfileRejected
	}
	q := profiledb.New(s.pool)
	if _, err := q.GetProfileRevision(ctx, profiledb.GetProfileRevisionParams{ProfileID: profileID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, 0, ErrProfileNotFound
		}
		return nil, 0, err
	}
	rows, err := q.ListProfileRevisions(ctx, profiledb.ListProfileRevisionsParams{ProfileID: profileID, BeforeRevision: before, PageLimit: pageSize + 1})
	if err != nil {
		return nil, 0, err
	}
	var next int64
	if len(rows) > int(pageSize) {
		rows = rows[:pageSize]
		next = rows[len(rows)-1].RevisionNumber
	}
	result := make([]*adminv1.ProfileSummary, 0, len(rows))
	for _, row := range rows {
		if !validRevisionMetadata(row) {
			return nil, 0, ErrProfileCorrupt
		}
		result = append(result, &adminv1.ProfileSummary{ProfileId: row.ProfileID.String(), RevisionId: row.ID.String(), RevisionNumber: uint64(row.RevisionNumber), Name: row.Name, Description: row.Description, ResourceCount: uint32(row.ResourceCount), ActorId: row.ActorID.String(), PublishedAt: timestamppb.New(row.PublishedAt.Time), SpecSha256: row.SpecDigest})
	}
	if err := nameSummaryActors(ctx, q, result); err != nil {
		return nil, 0, err
	}
	return result, next, nil
}

func validRevisionMetadata(row profiledb.ProfileRevision) bool {
	return row.ID != uuid.Nil && row.ProfileID != uuid.Nil && row.ActorID != uuid.Nil && row.RevisionNumber > 0 && row.ResourceCount >= 1 && row.ResourceCount <= 64 && len(row.SpecDigest) == sha256.Size && finiteProfileTime(row.PublishedAt)
}
