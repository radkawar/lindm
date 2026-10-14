// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"sync"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/policy/profiledb"
	"lindm/internal/protodata"
)

var (
	ErrProfileRejected = errors.New("profile request rejected")
	ErrProfileConflict = errors.New("profile revision conflict")
	ErrProfileNotFound = errors.New("profile revision not found")
	ErrProfileCorrupt  = errors.New("profile durable state is inconsistent")
	ErrProfileCapacity = errors.New("profile revision capacity exhausted")
)

// Store retains immutable catalog revisions. Publishing never changes a device
// assignment. Its mutation transaction is owned by the fresh-authorization caller.
type Store struct {
	pool  *pgxpool.Pool
	rules protovalidate.Validator
}

// Catalog rules are independent of the store's pool and revision state.
var catalogRules = sync.OnceValues(func() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(
		&adminv1.PublishProfileRevisionRequest{},
		&adminv1.GetProfileRevisionRequest{},
		&adminv1.ListProfilesRequest{},
	), protovalidate.WithDisableLazy())
})

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, ErrProfileRejected
	}
	rules, err := catalogRules()
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool, rules: rules}, nil
}

// Publish requires the caller's fresh principal lock. Lock order is principal,
// request reservation, profile. Exact retries precede head/clock/capacity checks;
// they return their original immutable revision and never advance a newer head.
func (s *Store) Publish(ctx context.Context, tx pgx.Tx, request *adminv1.PublishProfileRevisionRequest, actorID uuid.UUID) (*adminv1.ProfileRevision, error) {
	revision, err := s.publish(ctx, tx, request, actorID)
	if err != nil {
		return nil, err
	}
	names, err := actorNames(ctx, profiledb.New(tx), revision.GetActorId())
	if err != nil {
		return nil, err
	}
	revision.ActorDisplayName = names[revision.GetActorId()]
	return revision, nil
}

func (s *Store) publish(ctx context.Context, tx pgx.Tx, request *adminv1.PublishProfileRevisionRequest, actorID uuid.UUID) (*adminv1.ProfileRevision, error) {
	if tx == nil || actorID == uuid.Nil || request == nil {
		return nil, ErrProfileRejected
	}
	if err := protodata.ValidateClosed(request.ProtoReflect()); err != nil {
		return nil, ErrProfileRejected
	}
	if err := s.rules.Validate(request); err != nil {
		return nil, ErrProfileRejected
	}
	spec, specDigest, err := CanonicalSpec(ctx, request.GetSpec())
	if err != nil {
		return nil, profileInputError(ctx, err)
	}
	// Positions refer to the caller's order, before canonical resource sorting.
	if err := Publishable(request.GetSpec()); err != nil {
		return nil, err
	}
	requestID, err := uuid.Parse(request.GetRequestId())
	if err != nil {
		return nil, ErrProfileRejected
	}
	profileID, err := uuid.Parse(request.GetProfileId())
	if err != nil {
		return nil, ErrProfileRejected
	}
	var expected *uuid.UUID
	normalized := &adminv1.PublishProfileRevisionRequest{RequestId: requestID.String(), ProfileId: profileID.String(), Spec: spec, Reason: request.GetReason()}
	if request.ExpectedRevisionId != nil {
		id, err := uuid.Parse(request.GetExpectedRevisionId())
		if err != nil {
			return nil, ErrProfileRejected
		}
		expected = &id
		normalized.ExpectedRevisionId = proto.String(id.String())
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(normalized)
	if err != nil {
		return nil, ErrProfileRejected
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("lindm.resource-profile.publish.v1\x00"))
	_, _ = hash.Write(actorID[:])
	_, _ = hash.Write(encoded)
	digest := hash.Sum(nil)
	q := profiledb.New(tx)
	revisionID, auditID := uuid.New(), uuid.New()
	inserted, err := q.ReserveProfileRequest(ctx, profiledb.ReserveProfileRequestParams{RequestID: requestID, ActorID: actorID, RequestDigest: digest, ProfileID: profileID, RevisionID: revisionID, AuditID: auditID})
	if err != nil {
		return nil, err
	}
	if inserted == 0 {
		prior, err := q.GetProfileRequest(ctx, requestID)
		if err != nil {
			return nil, err
		}
		if prior.ActorID != actorID || prior.ProfileID != profileID || !bytes.Equal(prior.RequestDigest, digest) {
			return nil, ErrProfileConflict
		}
		return s.readRevision(ctx, q, prior.ProfileID, &prior.RevisionID)
	}
	created := false
	if expected == nil {
		count, err := q.CreateProfile(ctx, profiledb.CreateProfileParams{ID: profileID, HeadRevisionID: revisionID})
		if err != nil {
			return nil, err
		}
		if count != 1 {
			return nil, ErrProfileConflict
		}
		created = true
	}
	head, err := q.LockProfile(ctx, profileID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrProfileNotFound
	}
	if err != nil {
		return nil, err
	}
	var number int64 = 1
	previousTime := head.CreatedAt
	if !created {
		if expected == nil || head.HeadRevisionID != *expected {
			return nil, ErrProfileConflict
		}
		number, previousTime, err = s.successorOf(ctx, q, profileID, *expected)
		if err != nil {
			return nil, err
		}
	}
	now, err := q.ProfileClock(ctx)
	if err != nil {
		return nil, err
	}
	if !finiteProfileTime(now) || !finiteProfileTime(previousTime) || now.Time.Before(previousTime.Time) {
		return nil, ErrProfileRejected
	}
	if err := q.InsertProfileRevision(ctx, profiledb.InsertProfileRevisionParams{
		ID: revisionID, ProfileID: profileID, RevisionNumber: number, Name: spec.GetName(), Description: spec.GetDescription(), ResourceCount: int32(len(spec.GetResources())), SpecDigest: specDigest[:], ActorID: actorID, PublishedAt: now,
	}); err != nil {
		return nil, err
	}
	if err := insertRevisionResources(ctx, q, revisionID, spec); err != nil {
		return nil, err
	}
	if !created {
		count, err := q.AdvanceProfileHead(ctx, profiledb.AdvanceProfileHeadParams{NextID: revisionID, ProfileID: profileID, ExpectedID: *expected})
		if err != nil {
			return nil, err
		}
		if count != 1 {
			return nil, ErrProfileConflict
		}
	}
	if err := q.InsertProfileAudit(ctx, profiledb.InsertProfileAuditParams{ID: auditID, OccurredAt: now, ActorID: &actorID, ResourceID: profileID.String(), Reason: request.GetReason()}); err != nil {
		return nil, err
	}
	return &adminv1.ProfileRevision{ProfileId: profileID.String(), RevisionId: revisionID.String(), RevisionNumber: uint64(number), Spec: spec, ActorId: actorID.String(), PublishedAt: timestamppb.New(now.Time), SpecSha256: specDigest[:]}, nil
}

// successorOf validates the captured head revision before extending its
// immutable sequence, returning the next revision number and the head's
// publication time.
func (s *Store) successorOf(ctx context.Context, q *profiledb.Queries, profileID, head uuid.UUID) (int64, pgtype.Timestamptz, error) {
	previous, err := q.GetProfileRevision(ctx, profiledb.GetProfileRevisionParams{ProfileID: profileID, RevisionID: &head})
	if err != nil {
		return 0, pgtype.Timestamptz{}, err
	}
	if _, err := s.readRevisionRow(ctx, q, previous); err != nil {
		return 0, pgtype.Timestamptz{}, err
	}
	if previous.RevisionNumber == math.MaxInt64 {
		return 0, pgtype.Timestamptz{}, ErrProfileCapacity
	}
	return previous.RevisionNumber + 1, previous.PublishedAt, nil
}

// insertRevisionResources copies the revision's resources, without their
// dependency lists, and its dependency edges, requiring every row to be written.
func insertRevisionResources(ctx context.Context, q *profiledb.Queries, revisionID uuid.UUID, spec *policyv1.ResourceProfile) error {
	resources := make([]profiledb.InsertProfileResourcesParams, 0, len(spec.GetResources()))
	dependencyCount := 0
	for _, resource := range spec.GetResources() {
		dependencyCount += len(resource.GetDependsOn())
	}
	dependencies := make([]profiledb.InsertProfileDependenciesParams, 0, dependencyCount)
	for _, resource := range spec.GetResources() {
		resourceID, err := uuid.Parse(resource.GetResourceId())
		if err != nil {
			return ErrProfileRejected
		}
		record := proto.CloneOf(resource)
		record.DependsOn = nil
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(record)
		if err != nil {
			return ErrProfileRejected
		}
		ref := resource.GetDesired().GetRef()
		resources = append(resources, profiledb.InsertProfileResourcesParams{RevisionID: revisionID, ResourceID: resourceID, ResourceKind: int16(ref.GetKind()), CanonicalKey: ref.GetCanonicalKey(), ResourceProto: encoded})
		for _, dependency := range resource.GetDependsOn() {
			dependencies = append(dependencies, profiledb.InsertProfileDependenciesParams{RevisionID: revisionID, ResourceID: resourceID, DependencyKind: int16(dependency.GetRef().GetKind()), DependencyKey: dependency.GetRef().GetCanonicalKey(), Condition: int16(dependency.GetCondition())})
		}
	}
	copied, err := q.InsertProfileResources(ctx, resources)
	if err != nil {
		return err
	}
	if copied != int64(len(resources)) {
		return ErrProfileCorrupt
	}
	if len(dependencies) > 0 {
		copied, err = q.InsertProfileDependencies(ctx, dependencies)
		if err != nil {
			return err
		}
		if copied != int64(len(dependencies)) {
			return ErrProfileCorrupt
		}
	}
	return nil
}

func profileInputError(ctx context.Context, _ error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrProfileRejected
}

func finiteProfileTime(value pgtype.Timestamptz) bool {
	return value.Valid && value.InfinityModifier == pgtype.Finite && !value.Time.IsZero() && timestamppb.New(value.Time).CheckValid() == nil
}
